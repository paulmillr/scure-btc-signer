import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { hex, base64 } from '@scure/base';
import * as btc from '../../index.js';
import * as bip32 from '@scure/bip32';
import { default as f_transaction } from './fixtures/bitcoinjs/transaction.json' assert { type: 'json' };
import { default as f_script } from './fixtures/bitcoinjs/script.json' assert { type: 'json' };
import { default as f_address } from './fixtures/bitcoinjs/address.json' assert { type: 'json' };
import { default as psbt } from './fixtures/bitcoinjs/psbt.json' assert { type: 'json' };
import * as utils from './utils.js';

should('version is int32le', () => {
  const txHex = 'ffffffff0000ffffffff';
  const tx = btc.Transaction.fromRaw(hex.decode(txHex));
  deepStrictEqual(-1, tx.version);
  deepStrictEqual(0xffffffff, tx.lockTime);
});

for (let i = 0; i < f_transaction.valid.length; i++) {
  const v = f_transaction.valid[i];
  should(`Transaction/valid(${i}): ${v.description}`, () => {
    const opts = {
      allowUnknowOutput: i === 4 || i === 19,
      disableScriptCheck: i === 4 || i === 19,
    };
    const vhex = v.whex ? v.whex : v.hex;
    const tx = btc.Transaction.fromRaw(hex.decode(vhex), opts);
    deepStrictEqual(tx.weight, v.weight, 'weight');
    deepStrictEqual(tx.vsize, v.virtualSize, 'vsize');
    deepStrictEqual(tx.id, v.id, 'id');
    deepStrictEqual(tx.hash, v.hash, 'hash');
    if (v.whex) {
      deepStrictEqual(
        btc.Transaction.fromRaw(hex.decode(v.whex), opts).hasWitnesses,
        true,
        'hasWitnesses=true'
      );
    }
    if (v.hex) {
      deepStrictEqual(hex.encode(tx.toBytes(true)), v.hex, 'unsignedHex');
      deepStrictEqual(
        btc.Transaction.fromRaw(hex.decode(v.hex), opts).hasWitnesses,
        false,
        'hasWitnesses=false'
      );
    }
    // whex is signed hex
    //const wtx = btc.Transaction.fromRaw(hex.decode(v.whex));
  });
}

should(`Transaction/invalid`, () => {
  throws(() => btc.RawTx.decode(hex.decode(t.hex)));
});

for (let i = 0; i < f_script.valid.length; i++) {
  const v = f_script.valid[i];
  should(`Script/valid(${i}): ${v.description}`, () => {
    const fa = utils.fromASM(v.asm);
    const encoded = hex.encode(btc.Script.encode(fa));
    deepStrictEqual(encoded, v.script);
    deepStrictEqual(btc.Script.decode(hex.decode(v.script)), fa);
  });
}

for (let i = 0; i < f_transaction.hashForSignature.length; i++) {
  const v = f_transaction.hashForSignature[i];
  should(`Transaction/hashForSignature(${i}): ${v.description}`, () => {
    const opts = {
      allowUnknowOutput: [0, 1, 2, 3, 4].includes(i),
    };
    const tx = btc.Transaction.fromRaw(hex.decode(v.txHex), opts);
    const script = btc.Script.encode(utils.fromASM(v.script));
    const preimage = hex.encode(tx.preimageLegacy(v.inIndex, script, v.type));
    deepStrictEqual(preimage, v.hash);
  });
}

for (let i = 0; i < f_transaction.hashForWitnessV0.length; i++) {
  const v = f_transaction.hashForWitnessV0[i];
  should(`Transaction/hashForWitnessV0(${i}): ${v.description}`, () => {
    const tx = btc.Transaction.fromRaw(hex.decode(v.txHex));
    const script = btc.Script.encode(utils.fromASM(v.script));
    const preimage = hex.encode(tx.preimageWitnessV0(v.inIndex, script, v.type, BigInt(v.value)));
    deepStrictEqual(preimage, v.hash);
  });
}

for (let i = 0; i < f_transaction.taprootSigning.length; i++) {
  const v = f_transaction.taprootSigning[i];
  should(`Transaction/hashForWitnessV1(${i}): ${v.description}`, () => {
    const opts = {
      allowUnknowOutput: i === 0,
      disableScriptCheck: i === 0,
    };
    const tx = btc.Transaction.fromRaw(hex.decode(v.txHex), opts);
    const scripts = v.utxos.map((i) => hex.decode(i.scriptHex));
    const amounts = v.utxos.map((i) => BigInt(i.value));
    for (const c of v.cases) {
      const hashType = hex.decode(c.typeHex)[0];
      const preimage = tx.preimageWitnessV1(c.vin, scripts, hashType, amounts);
      deepStrictEqual(hex.encode(preimage), c.hash);
    }
  });
}

for (let i = 0; i < f_address.standard.length; i++) {
  if ([11, 12, 13].includes(i)) continue;
  const v = f_address.standard[i];
  const address = v.base58check || v.bech32;
  should(`Address/parseAddress(${i}): ${address}/${v.network}`, () => {
    const script = btc.Script.encode(utils.fromASM(v.script));
    const net = utils.getNet(v.network);
    deepStrictEqual(
      hex.encode(btc.OutScript.encode(btc.Address(net).decode(address))),
      hex.encode(script)
    );
  });
}

for (let i = 0; i < f_address.invalid.toOutputScript.length; i++) {
  const v = f_address.invalid.toOutputScript[i];
  should(`Address/parseAddress(${i}, invalid): ${v.address}`, () => {
    throws(() => btc.OutScript.encode(btc.Address(v.network).decode(v.address)));
  });
}

const SIGN_CASES = [
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: undefined,
    before:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000000000',
    after:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000002202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561473044022074ad44a29de3dfa8059d2c5069e415fe1a64eac01e456e4acf5e4a900b9a59ea02201ad37e8ed45f031cecc900b769636b06fc554db6d243ae0d8883b302d7864437010000',
  },
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: undefined,
    before:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000000000',
    after:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000002202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561473044022074ad44a29de3dfa8059d2c5069e415fe1a64eac01e456e4acf5e4a900b9a59ea02201ad37e8ed45f031cecc900b769636b06fc554db6d243ae0d8883b302d7864437010000',
  },
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: undefined,
    before:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000000000',
    after:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000002202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561473044022074ad44a29de3dfa8059d2c5069e415fe1a64eac01e456e4acf5e4a900b9a59ea02201ad37e8ed45f031cecc900b769636b06fc554db6d243ae0d8883b302d7864437010000',
  },
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: undefined,
    before:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000000000',
    after:
      '70736274ff0100330100000001755afab5af04637289f61710c953b5e9fdfaa0b4c6e1dc00cc5062b413c17d5d0000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9142f2ca4720ea62c3d8226843dde511a4318bd744788ac000000002202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561473044022074ad44a29de3dfa8059d2c5069e415fe1a64eac01e456e4acf5e4a900b9a59ea02201ad37e8ed45f031cecc900b769636b06fc554db6d243ae0d8883b302d7864437010000',
  },
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: undefined,
    before:
      '70736274ff01003301000000011d9dabc27005ac676d61d91b0d07771b94185720e9dbf1de982358c9be3f37f60000000000ffffffff0000000000000100bd0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006a47304402201fecdf882b5baec53c6f10ea1519a6cdb224fb8cc95f48309dd15631bfeb104d022041560cee283d4c8c752f3ad7d915e0c36cd6d9f30ab91b3f6d3f5e671ea3998c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f5050000000017a9145d87cc24e4d46217b54643865be22f159756053287000000000104695221026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561210201c61774a03fcdaa86fa8ca6d365b932c784bb730ec99cd29356103113363feb210205225f93dd9f74bc114637cb982470ab50ee03beb3865569150ec05e1330548b53ae0000',
    after:
      '70736274ff01003301000000011d9dabc27005ac676d61d91b0d07771b94185720e9dbf1de982358c9be3f37f60000000000ffffffff0000000000000100bd0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006a47304402201fecdf882b5baec53c6f10ea1519a6cdb224fb8cc95f48309dd15631bfeb104d022041560cee283d4c8c752f3ad7d915e0c36cd6d9f30ab91b3f6d3f5e671ea3998c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f5050000000017a9145d87cc24e4d46217b54643865be22f159756053287000000002202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb856147304402206a10021379a81a859976e0062de85241b85f70e0433d0f0d77d2a9e9bf9049be02206508b9537a5b01503b8a9b3ee2c5496db2348e7b73ae546b0bc3afba02ebae99010104695221026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561210201c61774a03fcdaa86fa8ca6d365b932c784bb730ec99cd29356103113363feb210205225f93dd9f74bc114637cb982470ab50ee03beb3865569150ec05e1330548b53ae0000',
  },
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: undefined,
    before:
      '70736274ff010033010000000186aaf8f74e518d8f9d5f6464a6bcd9796aacf0723aac07d93460dbe2d076ab360000000000ffffffff00000000000001012000e1f5050000000017a9149335e587a9af4836f4a7435db449978973ee894a8701041600142f2ca4720ea62c3d8226843dde511a4318bd74470000',
    after:
      '70736274ff010033010000000186aaf8f74e518d8f9d5f6464a6bcd9796aacf0723aac07d93460dbe2d076ab360000000000ffffffff00000000000001012000e1f5050000000017a9149335e587a9af4836f4a7435db449978973ee894a872202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561473044022017031a22422c733d0fffa43b288cc6ef4b74bf235de29dc57e6c400a6b30af200220298974b6b0c4deecd9266f5f59412779db9de14b77556f2ae48a807fddb0c1db0101041600142f2ca4720ea62c3d8226843dde511a4318bd74470000',
  },
  {
    wif: 'KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni',
    input: 0,
    sigHash: [129],
    before:
      '70736274ff010033010000000186aaf8f74e518d8f9d5f6464a6bcd9796aacf0723aac07d93460dbe2d076ab360000000000ffffffff00000000000001012000e1f5050000000017a9149335e587a9af4836f4a7435db449978973ee894a870103048100000001041600142f2ca4720ea62c3d8226843dde511a4318bd74470000',
    after:
      '70736274ff010033010000000186aaf8f74e518d8f9d5f6464a6bcd9796aacf0723aac07d93460dbe2d076ab360000000000ffffffff00000000000001012000e1f5050000000017a9149335e587a9af4836f4a7435db449978973ee894a872202026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb856147304402202410dffbd7ec7cb0f758a12d83419db9fd7897dc063fcf1d7ab5f022670f9403022071d8630a201b5110a93f8343e3e4f36d52af9d6a4e4f52a81e42db0eac0ec9c8810103048100000001041600142f2ca4720ea62c3d8226843dde511a4318bd74470000',
  },
];

//   2e890b939b58512d7cf78a11d5dc69d07992b27694531fa99fdeea23e07ad1e6
// 802e890b939b58512d7cf78a11d5dc69d07992b27694531fa99fdeea23e07ad1e6 01 95 5d 7f 5f
// KxnAnQh6UJBxLF8Weup77yn8tWhLHhDhnXeyJuzmmcZA5aRdMJni
for (let i = 0; i < SIGN_CASES.length; i++) {
  const v = SIGN_CASES[i];
  should(`PSBT sign(${i})`, () => {
    const opts = {
      bip174jsCompat: true,
    };
    const privKey = btc.WIF().decode(v.wif);
    const before = btc.Transaction.fromPSBT(hex.decode(v.before), opts);
    before.signIdx(privKey, v.input, v.sigHash);
    const after = btc.Transaction.fromPSBT(hex.decode(v.after), opts);
    deepStrictEqual(after, before);
    deepStrictEqual(hex.encode(before.toPSBT(undefined, true)), v.after);
  });
}

for (let i = 0; i < psbt.signInput.checks.length; i++) {
  const v = psbt.signInput.checks[i];
  should(`PSBT signInput(${i}): ${v.description}`, () => {
    for (const k of ['shouldSign', 'shouldThrow']) {
      const item = v[k];
      if (!item) continue;
      const tx = btc.Transaction.fromPSBT(base64.decode(item.psbt));
      const privKey = btc.WIF().decode(item.WIF);
      const fn = () => tx.signIdx(privKey, item.inputToCheck, item.sighashTypes);
      if (k === 'shouldSign') fn();
      if (k === 'shouldThrow') throws(fn);
    }
  });
}

const FINALIZE_CASES1 = [
  {
    unknownKeyVals: [],
    witnessUtxo: {
      script: '002021b56c5e26d75f0b02eee7b0a8c02f8f3297747e3f86dacd280b25d60bdacec0',
      value: 2000,
    },
    witnessScript: '76a914e2152c3d79c100335f3d160e6b412e7e0f11812f88ac',
    partialSig: [
      {
        pubkey: '03b9e7d482346fffef6de882bac235de49bdd05cfc25d0b383d67b4246c3382c3b',
        signature:
          '304402203bf31bd422eff8ef6b01712abfda9b01863c9b8dc7bd4f834e1087e3de0e01cd02202d037c26a61c109e8b5ec60c9483b7da12e5ee224817859349690fe50078f37401',
      },
    ],
    finalScriptWitness:
      '0347304402203bf31bd422eff8ef6b01712abfda9b01863c9b8dc7bd4f834e1087e3de0e01cd02202d037c26a61c109e8b5ec60c9483b7da12e5ee224817859349690fe50078f374012103b9e7d482346fffef6de882bac235de49bdd05cfc25d0b383d67b4246c3382c3b1976a914e2152c3d79c100335f3d160e6b412e7e0f11812f88ac',
    finalScriptSig: undefined,
  },
  {
    unknownKeyVals: [],
    sighashType: 1,
    nonWitnessUtxo:
      '0200000001f9f34e95b9d5c8abcd20fc5bd4a825d1517be62f0f775e5f36da944d9452e550000000006b483045022100c86e9a111afc90f64b4904bd609e9eaed80d48ca17c162b1aca0a788ac3526f002207bb79b60d4fc6526329bf18a77135dc5660209e761da46e1c2f1152ec013215801210211755115eabf846720f5cb18f248666fec631e5e1e66009ce3710ceea5b1ad13ffffffff01905f0100000000001976a9148bbc95d2709c71607c60ee3f097c1217482f518d88ac00000000',
    partialSig: [
      {
        pubkey: '0365db9da3f8a260078a7e8f8b708a1161468fb2323ffda5ec16b261ec1056f455',
        signature:
          '3045022100931b6db94aed25d5486884d83fc37160f37f3368c0d7f48c757112abefec983802205fda64cff98c849577026eb2ce916a50ea70626a7669f8596dd89b720a26b4d501',
      },
    ],
    finalScriptSig:
      '483045022100931b6db94aed25d5486884d83fc37160f37f3368c0d7f48c757112abefec983802205fda64cff98c849577026eb2ce916a50ea70626a7669f8596dd89b720a26b4d501210365db9da3f8a260078a7e8f8b708a1161468fb2323ffda5ec16b261ec1056f455',
    finalScriptWitness: undefined,
  },
  {
    nonWitnessUtxo:
      '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000',
    partialSig: [
      {
        pubkey: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
        signature:
          '3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01',
      },
      {
        pubkey: '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7',
        signature:
          '3045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01',
      },
    ],
    sighashType: 1,
    redeemScript:
      '5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
    bip32Derivation: [
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
        path: "m/0'/0'/0'",
      },
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7',
        path: "m/0'/0'/1'",
      },
    ],
    finalScriptSig:
      '00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
    finalScriptWitness: undefined,
  },
  {
    witnessUtxo: {
      script: 'a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887',
      value: 200000000,
    },
    partialSig: [
      {
        pubkey: '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        signature:
          '3044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01',
      },
      {
        pubkey: '023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73',
        signature:
          '3044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d201',
      },
    ],
    sighashType: 1,
    redeemScript: '00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
    witnessScript:
      '522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae',
    bip32Derivation: [
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73',
        path: "m/0'/0'/3'",
      },
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        path: "m/0'/0'/2'",
      },
    ],
    finalScriptSig: '2200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
    finalScriptWitness:
      '0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae',
  },
  {
    partialSig: [
      {
        pubkey: '033a4ae0d7985fec7204e2b29e30f70443c3abb10df1bad95e37b8f3c831b215f0',
        signature:
          '3045022100bdc7fd710f4406446e98c1c24b8ba942814aed489e96f6ae06a75cd15c63626c022012ad74ccdb138310aa7b9bb453cd8a81721aa5bdb97cf333bf0865bd49e3e3da01',
      },
    ],
    nonWitnessUtxo:
      '02000000016fb4cc98db39530104a5c70b1e569a334c371c41e187ce4d8eb50e6cb0ccb99b010000006b483045022100d5947af04172a7d1a47ebbac3b85a88f8a1eac5588a5f199233eebf8c4e591e30220603bfbd083612c62168e0f99506e66586b29912ee900e920a85e190ddb58623b01210282b3586923d4b27688eb79c23ea330eb40306247e74663018654f35b94bbacbeffffffff01905f0100000000002321033a4ae0d7985fec7204e2b29e30f70443c3abb10df1bad95e37b8f3c831b215f0ac00000000',
    finalScriptSig:
      '483045022100bdc7fd710f4406446e98c1c24b8ba942814aed489e96f6ae06a75cd15c63626c022012ad74ccdb138310aa7b9bb453cd8a81721aa5bdb97cf333bf0865bd49e3e3da01',
    finalScriptWitness: undefined,
  },
  {
    partialSig: [
      {
        pubkey: '035a0d5f453fe86c00b9523b247867783f78b26fe8f98adf4e744085d454323a08',
        signature:
          '3045022100864f876ef63a612841094981542938dac1561fd2d3c14bf6c1b442fed22e100c022040ff5249256377e974304deea4811c50f210e787314cd70f46efb454c088a3fb01',
      },
    ],
    nonWitnessUtxo:
      '020000000192ced72fceed912bac140dcbdaed8274978d92a4cca1b7a13cd9bfc24190533a010000006b483045022100cb73a82edac5203bffb9db8a8f4d290673d9e3ee29e685e53e1cf094975847600220080f7f48d3985b24c3464a89ab17b5d5584b041071f35ff9642f7be738ebb870012102fbbe6dfbab6c30b3c5f38bc4486fcfd672c4f2dd23587dc0c4fc825da7c8b615ffffffff01905f0100000000001976a914c7e76dfd05f4bdceb6f052dbe9013c23b9ae0b1988ac00000000',
    finalScriptSig:
      '483045022100864f876ef63a612841094981542938dac1561fd2d3c14bf6c1b442fed22e100c022040ff5249256377e974304deea4811c50f210e787314cd70f46efb454c088a3fb0121035a0d5f453fe86c00b9523b247867783f78b26fe8f98adf4e744085d454323a08',
    finalScriptWitness: undefined,
  },
  {
    nonWitnessUtxo:
      '0200000001301c0829528e15b6acead043db82cf721b6bc1e1368e25e43e04877499dd11fa000000006b483045022100935c870c788defd9aad6574820fa04a241424a644c118674ba0565370f2a50ed02201979f63f822695c39adc128264e13467142c8c1b47582d5e48567156911dfc7d0121022e725fc44c5baa6556b318dba862b6127a8f5c369a0aa1fdb3820045676e7fd9ffffffff01905f01000000000017a9148a10dec7a1fa7198ce423b303c39cee4822311328700000000',
    partialSig: [
      {
        pubkey: '02c59aea3b806f0e8e099a3b9007b82ff53af0daad0b75e91ed510a53c76445108',
        signature:
          '3045022100eaaa96753099cf8fa8a655c0000c2cf3422ac907855824d695d1f5dee7981e920220340b6e2275576d825f7eb08051f00dd96b959cb30349de2f0f593316475d02e101',
      },
      {
        pubkey: '03e76abb5182f4909d2276c9d46ec123d70dd5373f5610c2162c2bb5f37c6b9444',
        signature:
          '3045022100d9c30544168d2f210d33e275167de6b1992b72d608b219075358c7dfbe7814fc022012ba92d1f8a35ad527bb7a80645907039f2f816817cc43ea754530805ddeff1801',
      },
    ],
    redeemScript:
      '522102c59aea3b806f0e8e099a3b9007b82ff53af0daad0b75e91ed510a53c764451082102e17ef86febd11775cb8325f219e8e6139541d5fdd163f211794820c8d1e074b62103e76abb5182f4909d2276c9d46ec123d70dd5373f5610c2162c2bb5f37c6b94442103bde0e66feb23c3e2411949906ab9803b14fb0005967a500b5e56e130edf571ce54ae',
    finalScriptSig:
      '00483045022100eaaa96753099cf8fa8a655c0000c2cf3422ac907855824d695d1f5dee7981e920220340b6e2275576d825f7eb08051f00dd96b959cb30349de2f0f593316475d02e101483045022100d9c30544168d2f210d33e275167de6b1992b72d608b219075358c7dfbe7814fc022012ba92d1f8a35ad527bb7a80645907039f2f816817cc43ea754530805ddeff18014c8b522102c59aea3b806f0e8e099a3b9007b82ff53af0daad0b75e91ed510a53c764451082102e17ef86febd11775cb8325f219e8e6139541d5fdd163f211794820c8d1e074b62103e76abb5182f4909d2276c9d46ec123d70dd5373f5610c2162c2bb5f37c6b94442103bde0e66feb23c3e2411949906ab9803b14fb0005967a500b5e56e130edf571ce54ae',
    finalScriptWitness: undefined,
  },
  {
    nonWitnessUtxo:
      '0200000001972d810a2619dec96abab94bc04edbf145c835829fac9f6c425068bf3040c05b010000006b483045022100927e1f29e2c3e2a7796a2679062b3f576e1fb71f4378fc18debf46c85909fbaf02206ec7b52eff942a99298bf8b8e85996366fd4d6765b98eb32d3910588a2b9e663012102f528f52cbb3eee38cfce1964fad0310c413e90c9cb2f5694b40c19d188b94cbbffffffff01905f01000000000017a914fc288dc5821f6a04f5d5233262c2ddb74aff17968700000000',
    partialSig: [
      {
        pubkey: '02a3f3cae12709376719b4a74469fb10bfe9cc668fe23be350c73d63d637b880fb',
        signature:
          '304402204d185df56529a07625f6d5159a8277dfa7c9009227223758b286adbd1896f21802206398325a4a447887038dbc49f6b609d00820619008686e2202338f614de944a701',
      },
    ],
    redeemScript: '0014e2c66ea573f1aa172c381d60849c41bc7e1771eb',
    finalScriptSig: '160014e2c66ea573f1aa172c381d60849c41bc7e1771eb',
    finalScriptWitness:
      '0247304402204d185df56529a07625f6d5159a8277dfa7c9009227223758b286adbd1896f21802206398325a4a447887038dbc49f6b609d00820619008686e2202338f614de944a7012102a3f3cae12709376719b4a74469fb10bfe9cc668fe23be350c73d63d637b880fb',
  },
  {
    witnessUtxo: {
      script: '0014bc881a83b1d9bbb46377fba09890bf3079599806',
      value: 30000,
    },
    partialSig: [
      {
        pubkey: '02cdd737b3303e1ce2e7a04db81f275182b4de7f865258689b7b7bc9add4157320',
        signature:
          '304402205e180be46f35b573fb30068a26d03441a16ed7b6cba1c386ab15e60e821f614002200388ca7a683d2fdd4f3f4e9a0da1eefe648aa97b69bd123f3583771a6fa6c51c01',
      },
    ],
    finalScriptWitness:
      '0247304402205e180be46f35b573fb30068a26d03441a16ed7b6cba1c386ab15e60e821f614002200388ca7a683d2fdd4f3f4e9a0da1eefe648aa97b69bd123f3583771a6fa6c51c012102cdd737b3303e1ce2e7a04db81f275182b4de7f865258689b7b7bc9add4157320',
    finalScriptSig: undefined,
  },
  {
    witnessUtxo: {
      script: '0020b61f681387037c2e5a579f158245b90a9b47b08c69a58cc957c0b9913e9a4e8f',
      value: 30000,
    },
    partialSig: [
      {
        pubkey: '035f3609c59c43d2f6ce0f63f2396dece95a2004cd0e0345301281d49d78c334e9',
        signature:
          '3045022100b3b4c51a6ea8fdda5649be0cfca4aeda9ee9f3cd4a035b969f4af4c0309ad1c902200757966f64df158b8f67fe8f48485cafb47b0f5d73caa81c42f66da6d879696201',
      },
    ],
    witnessScript: '21035f3609c59c43d2f6ce0f63f2396dece95a2004cd0e0345301281d49d78c334e9ac',
    finalScriptWitness:
      '02483045022100b3b4c51a6ea8fdda5649be0cfca4aeda9ee9f3cd4a035b969f4af4c0309ad1c902200757966f64df158b8f67fe8f48485cafb47b0f5d73caa81c42f66da6d8796962012321035f3609c59c43d2f6ce0f63f2396dece95a2004cd0e0345301281d49d78c334e9ac',
    finalScriptSig: undefined,
  },
  {
    witnessUtxo: {
      script: '0020b61f681387037c2e5a579f158245b90a9b47b08c69a58cc957c0b9913e9a4e8f',
      value: 80000,
    },
    partialSig: [
      {
        pubkey: '035f3609c59c43d2f6ce0f63f2396dece95a2004cd0e0345301281d49d78c334e9',
        signature:
          '3045022100ba5cdeada68f6662565e8f80574928790f52ba6882c17d0e160565d4ac84b1eb022055ac4552ccfccb9f71275578b19d6a6ab1d7f6967e30998b29b97665269d8aca01',
      },
    ],
    witnessScript: '21035f3609c59c43d2f6ce0f63f2396dece95a2004cd0e0345301281d49d78c334e9ac',
    finalScriptWitness:
      '02483045022100ba5cdeada68f6662565e8f80574928790f52ba6882c17d0e160565d4ac84b1eb022055ac4552ccfccb9f71275578b19d6a6ab1d7f6967e30998b29b97665269d8aca012321035f3609c59c43d2f6ce0f63f2396dece95a2004cd0e0345301281d49d78c334e9ac',
    finalScriptSig: undefined,
  },
  {
    nonWitnessUtxo:
      '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000',
    partialSig: [
      {
        pubkey: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
        signature:
          '3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01',
      },
      {
        pubkey: '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7',
        signature:
          '3045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01',
      },
    ],
    sighashType: 1,
    redeemScript:
      '5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
    bip32Derivation: [
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
        path: "m/0'/0'/0'",
      },
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7',
        path: "m/0'/0'/1'",
      },
    ],
    finalScriptSig:
      '00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
    finalScriptWitness: undefined,
  },
  {
    witnessUtxo: {
      script: 'a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887',
      value: 200000000,
    },
    partialSig: [
      {
        pubkey: '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        signature:
          '3044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01',
      },
      {
        pubkey: '023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73',
        signature:
          '3044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d201',
      },
    ],
    sighashType: 1,
    redeemScript: '00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
    witnessScript:
      '522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae',
    bip32Derivation: [
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73',
        path: "m/0'/0'/3'",
      },
      {
        masterFingerprint: 'd90c6a4f',
        pubkey: '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        path: "m/0'/0'/2'",
      },
    ],
    finalScriptSig: '2200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
    finalScriptWitness:
      '0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae',
  },
];
for (let i = 0; i < FINALIZE_CASES1.length; i++) {
  const v = FINALIZE_CASES1[i];
  should(`PSBT finalize1(${i}): ${v.type}`, () => {
    if (v.witnessUtxo) v.witnessUtxo.script = hex.decode(v.witnessUtxo.script);
    if (v.partialSig) {
      v.partialSig = v.partialSig.map((i) => {
        return [hex.decode(i.pubkey), hex.decode(i.signature)];
      });
    }
    if (v.nonWitnessUtxo) v.nonWitnessUtxo = btc.RawTx.decode(hex.decode(v.nonWitnessUtxo));
    if (v.redeemScript) v.redeemScript = hex.decode(v.redeemScript);
    if (v.witnessScript) v.witnessScript = hex.decode(v.witnessScript);
    if (v.nonWitnessUtxo && !v.index) v.index = 0;

    const tx = new btc.Transaction();
    tx.inputs[0] = { ...v, finalScriptWitness: undefined, finalScriptSig: undefined };
    tx.finalize();

    const fs = tx.inputs[0].finalScriptSig ? hex.encode(tx.inputs[0].finalScriptSig) : undefined;
    const fw = tx.inputs[0].finalScriptWitness
      ? hex.encode(btc.RawWitness.encode(tx.inputs[0].finalScriptWitness))
      : undefined;
    deepStrictEqual(fw, v.finalScriptWitness);
    deepStrictEqual(fs, v.finalScriptSig);
  });
}

for (let i = 0; i < psbt.bip174.extractor.length; i++) {
  const v = psbt.bip174.extractor[i];
  should(`PSBT/extract(${i})`, () => {
    const tx = btc.Transaction.fromPSBT(base64.decode(v.psbt));
    deepStrictEqual(hex.encode(tx.extract()), v.transaction);
  });
}

const FINALIZE_CASES = psbt.finalizeAllInputs.concat(psbt.bip174.finalizer);
for (let i = 0; i < FINALIZE_CASES.length; i++) {
  const v = FINALIZE_CASES[i];
  should(`PSBT finalize(${i}): ${v.type}`, () => {
    const [before, after] = [v.psbt, v.result].map(base64.decode);
    const tx = btc.Transaction.fromPSBT(before);
    tx.finalize();
    deepStrictEqual(hex.encode(tx.toPSBT(0, true)), hex.encode(after));
  });
}

const PSBT_SIGN_HD = [
  {
    xprv: 'xprv9s21ZrQH143K2XNCa3o3tii6nbyJAET6GjTfzcF6roTjAMzLUBe8nt7QHNYqKah8JBv8V67MTWBCqPptRr6khjTSvCUVru78KHW13Viwnev',
    input: 0,
    before:
      '70736274ff01003301000000011b44a6db19372753f4187d039a6dc08673f3bc87f0d5f0cebd5b8c9a2b0191000000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9149597358d95a7b139a4d39ecbae2b9e1860525a2188ac000000002206039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d918042a69b22c000080000000800000008000000000000000000000',
    after:
      '70736274ff01003301000000011b44a6db19372753f4187d039a6dc08673f3bc87f0d5f0cebd5b8c9a2b0191000000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9149597358d95a7b139a4d39ecbae2b9e1860525a2188ac000000002202039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d947304402200e3e8e5c25326c12f5e9886a3bfc1a9c08d55b5f5485100761794f2300a9c78b02205c2806b6a41d9ee821aaac411f2d310a848807b3c681fba8b98b0c4dcb5c901a012206039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d918042a69b22c000080000000800000008000000000000000000000',
  },
  {
    xprv: 'xprv9s21ZrQH143K2XNCa3o3tii6nbyJAET6GjTfzcF6roTjAMzLUBe8nt7QHNYqKah8JBv8V67MTWBCqPptRr6khjTSvCUVru78KHW13Viwnev',
    input: 0,
    before:
      '70736274ff01003301000000011b44a6db19372753f4187d039a6dc08673f3bc87f0d5f0cebd5b8c9a2b0191000000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9149597358d95a7b139a4d39ecbae2b9e1860525a2188ac000000002206039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d918042a69b22c000080000000800000008000000000000000000000',
    after:
      '70736274ff01003301000000011b44a6db19372753f4187d039a6dc08673f3bc87f0d5f0cebd5b8c9a2b0191000000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9149597358d95a7b139a4d39ecbae2b9e1860525a2188ac000000002202039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d947304402200e3e8e5c25326c12f5e9886a3bfc1a9c08d55b5f5485100761794f2300a9c78b02205c2806b6a41d9ee821aaac411f2d310a848807b3c681fba8b98b0c4dcb5c901a012206039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d918042a69b22c000080000000800000008000000000000000000000',
  },
  {
    xprv: 'xprv9s21ZrQH143K2XNCa3o3tii6nbyJAET6GjTfzcF6roTjAMzLUBe8nt7QHNYqKah8JBv8V67MTWBCqPptRr6khjTSvCUVru78KHW13Viwnev',
    input: 0,
    before:
      '70736274ff01003301000000011b44a6db19372753f4187d039a6dc08673f3bc87f0d5f0cebd5b8c9a2b0191000000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9149597358d95a7b139a4d39ecbae2b9e1860525a2188ac000000002206039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d918042a69b22c000080000000800000008000000000000000000000',
    after:
      '70736274ff01003301000000011b44a6db19372753f4187d039a6dc08673f3bc87f0d5f0cebd5b8c9a2b0191000000000000ffffffff0000000000000100c00200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000006b4830450221008ed08f523d2fc772391c540a014587374bc29d3d7b8dde35fe899be27a1babfb022008a549e4158b89aaca48016ecf96cfa3f2a9d313862da04f8eb7bf890f5a4e9c0121026928a14e07a3eb3c985102d690f9c1c7af2639418222e5dc59b643300adb8561ffffffff0100e1f505000000001976a9149597358d95a7b139a4d39ecbae2b9e1860525a2188ac000000002202039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d947304402200e3e8e5c25326c12f5e9886a3bfc1a9c08d55b5f5485100761794f2300a9c78b02205c2806b6a41d9ee821aaac411f2d310a848807b3c681fba8b98b0c4dcb5c901a012206039fce6f4a0e6b951db97dde0c394d8036c1683beabcdbccee388ff96fcb63f3d918042a69b22c000080000000800000008000000000000000000000',
  },
];

for (let i = 0; i < PSBT_SIGN_HD.length; i++) {
  const v = PSBT_SIGN_HD[i];
  should(`PSBT sign (HDKey): ${i}`, () => {
    const opts = {
      bip174jsCompat: true,
    };
    const key = bip32.HDKey.fromExtendedKey(v.xprv);
    const tx = btc.Transaction.fromPSBT(hex.decode(v.before), opts);
    tx.signIdx(key, v.input);
    deepStrictEqual(hex.encode(tx.toPSBT(0, true)), v.after);
  });
}

for (let i = 0; i < psbt.signInputHD.checks.length; i++) {
  const v = psbt.signInputHD.checks[i];
  should(`PSBT sign (HDKey): ${v.description}`, () => {
    if (v.shouldSign) {
      const t = v.shouldSign;
      const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
      tx.sign(bip32.HDKey.fromExtendedKey(t.xprv));
    }
    if (v.shouldThrow) {
      const t = v.shouldThrow;
      throws(() => {
        const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
        tx.sign(bip32.HDKey.fromExtendedKey(t.xprv));
      });
    }
  });
}

for (let i = 0; i < psbt.addInput.checks.length; i++) {
  const t = psbt.addInput.checks[i];
  should(`PSBT/addInput(${i}): ${t.description}`, () => {
    const tx = new btc.Transaction();
    const data = {};
    for (const k in t.inputData) {
      const val = t.inputData[k];
      data[k] =
        typeof val === 'string' ? val.replace("Buffer.from('", '').replace("', 'hex')", '') : val;
    }
    console.log('Z', data);

    try {
      tx.addInput(data);
    } catch (e) {
      console.log('E', e);
    }
    //throws(() => tx.addInput(data));
  });
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

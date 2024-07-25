import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import { hex } from '@scure/base';
import * as btc from '../lib/esm/index.js';
import { secp256k1, schnorr as secp256k1_schnorr } from '@noble/curves/secp256k1';
import * as P from 'micro-packed';

describe('UTXO Select', () => {
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

  const names = {
    spend1_1: 'p2sh-p2pk',
    spend1_2: 'p2wsh-p2pk',
    spend1_3: 'p2sh-p2wsh-p2pk',
    spend2_1: 'p2sh-p2pkh',
    spend2_2: 'p2wsh-p2pkh',
    spend2_3: 'p2sh-p2wsh-p2pkh',
    spend2_4: 'p2pkh',
    spend3_1: 'p2sh-p2wpkh',
    spend3_2: 'p2wpkh',
    spend4_1: 'p2sh-p2ms',
    spend4_2: 'p2wsh-p2ms',
    spend4_3: 'p2sh-p2wsh-p2ms',
    spend4_4: 'ms(1-3)',
    spend4_5: 'ms(2-3)',
    spend4_6: 'ms(2-4)',
    spend5_1: 'p2tr keysig',
    spend5_2: 'tr(undefined, tr)',
    spend5_3: 'tr(keysig, tr)',
    spend5_4: 'p2tr-p2tr_ns(2)',
    spend5_5: 'p2tr-p2tr_ms(2)',
    spend5_6: 'p2tr-p2tr_ns(3)',
    spend5_7: 'p2tr-p2tr_ms(3)',
    spend5_8: 'tr-ns(1-3)',
    spend5_9: 'tr-ns(2-3)',
    spend5_10: 'tr-ns(2-4)',
    spend5_11: 'tr-ms(1-3)',
    spend5_12: 'tr-ms(2-3)',
    spend5_13: 'tr-ms(2-4)',
  };

  const INPUTS = [];
  for (let index = 0; index < spends.length; index++) {
    const { spend, name, privKeys } = spends[index];
    if (!enabled.includes(name)) continue;
    INPUTS.push({
      ...spend,
      txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
      index,
      witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') },
      privKeys,
      name,
    });
  }
  // Output
  const privOut = hex.decode('0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e');
  // TODO: btc.getPublic with types or something?
  const pubOut = secp256k1.getPublicKey(privOut, true);
  const out = btc.p2wpkh(pubOut, regtest);
  const OUTPUTS = [
    { address: out.address, amount: 1n }, // basic
    { address: btc.p2sh(btc.p2pk(P1), regtest).address, amount: 1n },
    { address: btc.p2wsh(btc.p2pk(P1), regtest).address, amount: 1n },
    { address: btc.p2sh(btc.p2wsh(btc.p2pk(P1)), regtest).address, amount: 1n },
    { address: btc.p2sh(btc.p2pkh(P2), regtest).address, amount: 1n },
    { address: btc.p2wsh(btc.p2pkh(P2), regtest).address, amount: 1n },
    { address: btc.p2sh(btc.p2wsh(btc.p2pkh(P2)), regtest).address, amount: 1n },
    { address: btc.p2pkh(P2, regtest).address, amount: 1n },
    { address: btc.p2sh(btc.p2wpkh(P3), regtest).address, amount: 1n },
    { address: btc.p2wpkh(P3, regtest).address, amount: 1n },
    { address: btc.p2sh(btc.p2ms(1, [P4, P5, P6]), regtest).address, amount: 1n },
    { address: btc.p2tr(P7S, undefined, regtest).address, amount: 1n },
    { address: btc.p2tr(undefined, [btc.p2tr_pk(P8S)], regtest).address, amount: 1n },
    { address: btc.p2tr(P7S, [btc.p2tr_pk(P8S)], regtest).address, amount: 1n },
  ];
  should('estimate size', () => {
    const t = (inputs, outputs, diff = 0, trLeafSize) => {
      const name = `${names[inputs[0].name]}/${names[outputs[0].name]}`;
      const FEE = 3n;
      // Taproot estimation is precise, but you have to pass sighash if you want to use non-default one,
      // because it changes signature size. For complex taproot trees you need to filter tapLeafScript
      // to include only leafs which you can sign we estimate size with smallest leaf (same as finalization),
      // but in specific case keys for this leaf can be unavailable (complex multisig)
      const _inputs = inputs.map((i) => {
        const res = { ...i };
        if (trLeafSize) {
          res.tapLeafScript = res.tapLeafScript.filter(
            ([cb, _]) => btc.TaprootControlBlock.encode(cb).length === trLeafSize
          );
        }
        return res;
      });
      const s = btc.selectUTXO(_inputs, [], 'all', {
        changeAddress: outputs[0].address,
        feePerByte: FEE,
        allowLegacyWitnessUtxo: true,
        network: regtest,
      });
      for (const i of inputs) {
        for (const pk of i.privKeys) s.tx.sign(pk, undefined, new Uint8Array(32));
      }
      s.tx.finalize();
      const real = { weight: s.tx.weight, vsize: s.tx.vsize, fee: s.tx.fee, weight: s.tx.weight };
      const estVsize = real.fee / FEE;
      const estFee = real.fee / BigInt(real.vsize);

      deepStrictEqual(estFee, FEE);
      deepStrictEqual(s.fee, real.fee);
      // estimated weight can be bigger than real by couple bytes (signature size difference):
      // - but never smaller!
      deepStrictEqual(diff >= 0, true);
      // - sig in witness: weight=1
      // - sig in script: weight=4 (legacy tx)
      // - multi sig have multiple signatures, so max difference is (1..4)*sigNum
      // - also, script encoding size can change (!!!)
      // - taproot is always exact!
      deepStrictEqual(s.weight - diff, real.weight);
    };
    // These manually verified that all differences is reasonable.
    // Don't do mass editing here.

    // Basic
    t([INPUTS[0]], [OUTPUTS[0]], 4); // p2sh-p2pk
    t([INPUTS[1]], [OUTPUTS[0]], 1); // p2wsh-p2pk
    t([INPUTS[2]], [OUTPUTS[0]], 1); // p2sh-p2wsh-p2pk
    t([INPUTS[3]], [OUTPUTS[0]]); // p2sh-p2pkh
    t([INPUTS[4]], [OUTPUTS[0]], 1); // p2wsh-p2pkh
    t([INPUTS[5]], [OUTPUTS[0]]); // p2sh-p2wsh-p2pkh
    t([INPUTS[6]], [OUTPUTS[0]], 4); // p2pkh
    t([INPUTS[7]], [OUTPUTS[0]], 1); // p2sh-p2wpkh
    t([INPUTS[8]], [OUTPUTS[0]], 1); // p2wpkh
    // MS
    t([INPUTS[9]], [OUTPUTS[0]], 4); // p2sh-p2ms (2-3)
    t([INPUTS[10]], [OUTPUTS[0]], 2); // p2wsh-p2ms (2-3)
    t([INPUTS[11]], [OUTPUTS[0]], 1); // p2sh-p2wsh-p2ms (2-3)
    t([INPUTS[12]], [OUTPUTS[0]]); // ms(1-3)
    t([INPUTS[13]], [OUTPUTS[0]], 4); // ms(1-3)
    t([INPUTS[14]], [OUTPUTS[0]], 4); // ms(1-3)
    t([INPUTS[15]], [OUTPUTS[0]], 4); // ms(1-3)
    t([INPUTS[16]], [OUTPUTS[0]]); // ms(1-3)
    t([INPUTS[17]], [OUTPUTS[0]]); // ms(1-3)
    t([INPUTS[18]], [OUTPUTS[0]], 4); // ms(1-3)
    t([INPUTS[19]], [OUTPUTS[0]], 4); // ms(2-3)
    t([INPUTS[20]], [OUTPUTS[0]]); // ms(2-3)
    // This looks very suspicious, but:
    // - real script length 252 (est 254)
    // - varint encoding: -> { real: 253, est: 257 } (4 bytes diff)
    // - 4*4 (legacy) -> 16
    t([INPUTS[21]], [OUTPUTS[0]], 16); // ms(2-3)
    t([INPUTS[22]], [OUTPUTS[0]]); // ms(2-3)
    t([INPUTS[23]], [OUTPUTS[0]]); // ms(2-4)
    t([INPUTS[24]], [OUTPUTS[0]], 4); // ms(2-4)
    t([INPUTS[25]], [OUTPUTS[0]], 4); // ms(2-4)
    t([INPUTS[26]], [OUTPUTS[0]]); // ms(2-4)
    t([INPUTS[27]], [OUTPUTS[0]], 4); // ms(2-4)
    t([INPUTS[28]], [OUTPUTS[0]], 4); // ms(2-4)
    t([INPUTS[29]], [OUTPUTS[0]], 8); // ms(2-4)
    t([INPUTS[30]], [OUTPUTS[0]]); // ms(2-4)
    t([INPUTS[31]], [OUTPUTS[0]], 4); // ms(2-4)
    t([INPUTS[32]], [OUTPUTS[0]], 4); // ms(2-4)
    t([INPUTS[33]], [OUTPUTS[0]], 4); // ms(2-4)
    // TR
    t([INPUTS[34]], [OUTPUTS[0]]); // p2tr keysig
    t([INPUTS[35]], [OUTPUTS[0]]); // tr(undefined, tr)
    t([INPUTS[36]], [OUTPUTS[0]]); // tr(keysig, tr)
    t([INPUTS[37]], [OUTPUTS[0]]); // p2tr-p2tr_ns(2)
    t([INPUTS[38]], [OUTPUTS[0]]); // p2tr-p2tr_ms(2)
    t([INPUTS[39]], [OUTPUTS[0]]); // p2tr-p2tr_ns(3)
    t([INPUTS[40]], [OUTPUTS[0]]); // p2tr-p2tr_ms(3)
    // TR NS
    t([INPUTS[41]], [OUTPUTS[0]]); // tr-ns(1-3)
    t([INPUTS[42]], [OUTPUTS[0]]); // tr-ns(1-3)
    t([INPUTS[43]], [OUTPUTS[0]]); // tr-ns(1-3)
    t([INPUTS[44]], [OUTPUTS[0]], 0, 97); // tr-ns(1-3)
    t([INPUTS[45]], [OUTPUTS[0]]); // tr-ns(1-3)
    t([INPUTS[46]], [OUTPUTS[0]], 0, 97); // tr-ns(1-3)
    t([INPUTS[47]], [OUTPUTS[0]], 0, 97); // tr-ns(1-3)
    t([INPUTS[48]], [OUTPUTS[0]]); // tr-ns(2-3)
    t([INPUTS[49]], [OUTPUTS[0]]); // tr-ns(2-3)
    t([INPUTS[50]], [OUTPUTS[0]], 0, 97); // tr-ns(2-3)
    t([INPUTS[51]], [OUTPUTS[0]], 0, 97); // tr-ns(2-3)
    t([INPUTS[52]], [OUTPUTS[0]]); // tr-ns(2-4)
    t([INPUTS[53]], [OUTPUTS[0]], 0, 129); // tr-ns(2-4)
    t([INPUTS[54]], [OUTPUTS[0]]); // tr-ns(2-4)
    t([INPUTS[55]], [OUTPUTS[0]]); // tr-ns(2-4)
    t([INPUTS[56]], [OUTPUTS[0]]); // tr-ns(2-4)
    t([INPUTS[57]], [OUTPUTS[0]], 0, 129); // tr-ns(2-4)
    t([INPUTS[58]], [OUTPUTS[0]], 0, 129); // tr-ns(2-4)
    t([INPUTS[59]], [OUTPUTS[0]], 0, 129); // tr-ns(2-4)
    t([INPUTS[60]], [OUTPUTS[0]], 0, 129); // tr-ns(2-4)
    t([INPUTS[61]], [OUTPUTS[0]], 0); // tr-ns(2-4)
    t([INPUTS[62]], [OUTPUTS[0]], 0); // tr-ns(2-4)
    // TR MS
    t([INPUTS[63]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[64]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[65]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[66]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[67]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[68]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[69]], [OUTPUTS[0]]); // tr-ms(1-3)
    t([INPUTS[70]], [OUTPUTS[0]]); // tr-ms(2-3)
    t([INPUTS[71]], [OUTPUTS[0]]); // tr-ms(2-3)
    t([INPUTS[72]], [OUTPUTS[0]]); // tr-ms(2-3)
    t([INPUTS[73]], [OUTPUTS[0]]); // tr-ms(2-3)
    t([INPUTS[74]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[75]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[76]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[77]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[78]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[79]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[80]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[81]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[82]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[83]], [OUTPUTS[0]]); // tr-ms(2-4)
    t([INPUTS[84]], [OUTPUTS[0]]); // tr-ms(2-4)
    // Outputs
    // for input[0] difference can be only 0 or 4 (depends on how lucky we are with signature)
    t([INPUTS[0]], [OUTPUTS[1]], 4);
    t([INPUTS[0]], [OUTPUTS[2]]);
    t([INPUTS[0]], [OUTPUTS[3]], 4);
    t([INPUTS[0]], [OUTPUTS[4]]);
    t([INPUTS[0]], [OUTPUTS[5]]);
    t([INPUTS[0]], [OUTPUTS[6]]);
    t([INPUTS[0]], [OUTPUTS[7]]);
    t([INPUTS[0]], [OUTPUTS[8]]);
    t([INPUTS[0]], [OUTPUTS[9]], 4);
    t([INPUTS[0]], [OUTPUTS[10]], 4);
    t([INPUTS[0]], [OUTPUTS[11]], 4);
    t([INPUTS[0]], [OUTPUTS[12]], 4);
    t([INPUTS[6]], [OUTPUTS[13]]);
  });

  should('estimating size of custom scripts', () => {
    const customScripts = [
      {
        encode(from) {
          const res = { type: 'tr_ord_reveal' };
          res.inscriptions = ['test'];
          res.pubkey = from[0];
          return res;
        },
        decode: (to) => {
          if (to.type !== 'tr_ord_reveal') return;
          const out = [to.pubkey, 'CHECKSIG'];
          out.push(
            0,
            'IF',
            new Uint8Array(['o'.charCodeAt(0), 'r'.charCodeAt(0), 'd'.charCodeAt(0)])
          );
          // Body
          out.push(0);
          out.push(new Uint8Array([1, 2, 3]));
          out.push('ENDIF');
          return out;
        },
        finalizeTaproot: (script, parsed, signatures) => {
          if (signatures.length !== 1)
            throw new Error('tr_ord_reveal/finalize: wrong signatures array');
          const [{ pubKey }, sig] = signatures[0];
          if (!P.utils.equalBytes(pubKey, parsed.pubkey)) return;
          return [sig, script];
        },
      },
    ];
    const p2tr_ord_reveal = (pubkey, inscriptions) => {
      return {
        type: 'tr_ord_reveal',
        script: P.apply(btc.Script, customScripts[0]).encode({
          type: 'tr_ord_reveal',
          pubkey,
          inscriptions,
        }),
      };
    };

    const privKey = hex.decode('0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a');
    const pubKey = secp256k1_schnorr.getPublicKey(privKey);
    const payment = btc.p2tr(
      undefined,
      p2tr_ord_reveal(pubKey, []),
      regtest,
      undefined,
      customScripts
    );
    // Test custom scripts inside tx just in case
    const tx = new btc.Transaction({ customScripts });
    tx.addInput({
      txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
      index: 0,
      witnessUtxo: { script: payment.script, amount: 100n },
      ...payment,
    });
    tx.addOutputAddress('bcrt1qg975h6gdx5mryeac72h6lj2nzygugxhy5n57q2', 80n, regtest);
    tx.sign(privKey, undefined, new Uint8Array(32));
    tx.finalize();
    // Actual utxo
    const s = btc.selectUTXO(
      [
        {
          txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
          index: 0,
          witnessUtxo: { script: payment.script, amount: 1000n },
          ...payment,
        },
      ],
      [],
      'all',
      {
        changeAddress: 'bcrt1qg975h6gdx5mryeac72h6lj2nzygugxhy5n57q2',
        feePerByte: 1n,
        network: regtest,
        customScripts,
      }
    );
    s.tx.sign(privKey, undefined, new Uint8Array(32));
    s.tx.finalize();
    deepStrictEqual(s.tx.weight, s.weight);
    deepStrictEqual(tx.weight, s.weight);
  });

  should('estimator', () => {
    const inp = (i, amount) => ({
      ...INPUTS[i],
      witnessUtxo: { ...INPUTS[i].witnessUtxo, amount: BigInt(amount) },
    });

    const INP = [
      inp(0, 10_000),
      inp(1, 15_000),
      inp(2, 75_000),
      inp(3, 125_000),
      inp(4, 5_000),
      inp(5, 25_000),
      inp(6, 150_000),
    ];
    const est = new btc._Estimator(INP, [OUTPUTS[0]], {
      feePerByte: 1n,
      changeAddress: '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      network: regtest,
      allowLegacyWitnessUtxo: true,
    });
    deepStrictEqual(est.biggest, [6, 3, 2, 5, 1, 0, 4]);
    deepStrictEqual(est.smallest, [4, 0, 1, 5, 2, 3, 6]);
    deepStrictEqual(est.oldest, [0, 1, 2, 3, 4, 5, 6]);
    deepStrictEqual(est.newest, [6, 5, 4, 3, 2, 1, 0]);
  });

  should('accumulate', () => {
    const inputs = [];
    let inputsTotalAmount = 0n;
    for (let i = 0; i < 25; i++) {
      const amount = 1n << BigInt(i);
      inputsTotalAmount += amount;
      inputs.push({
        ...INPUTS[0],
        witnessUtxo: { ...INPUTS[0].witnessUtxo, amount },
      });
    }
    const FEE = 1n;
    const est = new btc._Estimator(inputs, [{ ...OUTPUTS[0], amount: 100n }], {
      feePerByte: FEE,
      changeAddress: '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      network: regtest,
      allowLegacyWitnessUtxo: true,
      allowSameUtxo: true,
    });

    const t = (est, i, exact, skipNegative) => {
      const tx = new btc.Transaction({ network: regtest, allowLegacyWitnessUtxo: true });
      const acc = est.accumulate(i, exact, skipNegative);
      if (!acc) return;
      const { indices, fee } = acc;
      for (const idx of indices) {
        tx.addInput(inputs[idx]);
      }
      tx.addOutputAddress(OUTPUTS[0].address, est.amount, regtest);
      tx.sign(privKey1);
      tx.finalize();
      const expFee = BigInt(tx.vsize) * FEE;
      const change = tx.fee - expFee;
      deepStrictEqual(expFee <= fee, true);
      return {
        amounts: indices.map((i) => inputs[i].witnessUtxo.amount),
        change,
        expFee,
        fee,
      };
    };

    // cross-checked with coinSelect
    deepStrictEqual(t(est, est.biggest), {
      amounts: [16777216n],
      change: 16776925n,
      expFee: 191n,
      fee: 191n,
    });
    deepStrictEqual(
      est.default().indices.map((i) => 1n << BigInt(i)),
      t(est, est.biggest).amounts
    );
    deepStrictEqual(t(est, est.smallest), {
      amounts: [256n, 512n],
      change: 329n,
      expFee: 339n,
      fee: 341n,
    });
    // Exact
    deepStrictEqual(t(est, est.biggest, true, false), undefined);
    deepStrictEqual(t(est, est.smallest, true, false), undefined);
    // This works exact as coinselect
    est.amount = 256n;
    deepStrictEqual(t(est, est.biggest, true), {
      amounts: [512n],
      change: 66n,
      expFee: 190n,
      fee: 191n,
    });
    deepStrictEqual(
      est.default().indices.map((i) => 1n << BigInt(i)),
      t(est, est.biggest, true).amounts
    );
    deepStrictEqual(t(est, est.smallest, true, false), {
      amounts: [1n, 2n, 4n, 8n, 16n, 32n, 64n, 128n, 256n, 512n, 1024n],
      change: 106n,
      expFee: 1685n,
      fee: 1691n,
    });
    est.amount = 322n;
    deepStrictEqual(t(est, est.biggest, true), {
      amounts: [512n, 256n],
      change: 107n,
      expFee: 339n,
      fee: 341n,
    });
    deepStrictEqual(
      est.default().indices.map((i) => 1n << BigInt(i)),
      t(est, est.biggest, true).amounts
    );
    est.amount = 321n;
    deepStrictEqual(t(est, est.biggest, true), {
      amounts: [512n],
      change: 0n,
      expFee: 191n,
      fee: 191n,
    });
    deepStrictEqual(
      est.default().indices.map((i) => 1n << BigInt(i)),
      t(est, est.biggest, true).amounts
    );

    est.amount = 100n;
    const strategies = [
      'all',
      'default',

      'accumNewest',
      'accumOldest',
      'accumSmallest',
      'accumBiggest',

      'exactNewest/accumNewest',
      'exactNewest/accumOldest',
      'exactNewest/accumSmallest',
      'exactNewest/accumBiggest',

      'exactOldest/accumNewest',
      'exactOldest/accumOldest',
      'exactOldest/accumSmallest',
      'exactOldest/accumBiggest',

      'exactSmallest/accumNewest',
      'exactSmallest/accumOldest',
      'exactSmallest/accumSmallest',
      'exactSmallest/accumBiggest',

      'exactBiggest/accumNewest',
      'exactBiggest/accumOldest',
      'exactBiggest/accumSmallest',
      'exactBiggest/accumBiggest',
    ];
    deepStrictEqual(Object.fromEntries(strategies.map((i) => [i, est.select(i)])), {
      all: {
        // inputs which cost more to add than provided value is skipped
        indices: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
        fee: 2591n,
        weight: 10364,
        total: 33554176n,
      },
      default: { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      accumNewest: { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      accumOldest: { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      accumSmallest: { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      accumBiggest: { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactNewest/accumNewest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactNewest/accumOldest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactNewest/accumSmallest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactNewest/accumBiggest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactOldest/accumNewest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactOldest/accumOldest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactOldest/accumSmallest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactOldest/accumBiggest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactSmallest/accumNewest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactSmallest/accumOldest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactSmallest/accumSmallest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactSmallest/accumBiggest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactBiggest/accumNewest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
      'exactBiggest/accumOldest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactBiggest/accumSmallest': { indices: [8, 9], fee: 341n, weight: 1364, total: 768n },
      'exactBiggest/accumBiggest': { indices: [24], fee: 191n, weight: 764, total: 16777216n },
    });

    const t2 = (strategy, amount) => {
      const est = new btc._Estimator(inputs, [{ ...OUTPUTS[0], amount }], {
        feePerByte: FEE,
        changeAddress: '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
        network: regtest,
        allowLegacyWitnessUtxo: true,
        createTx: true,
        allowSameUtxo: true,
      });
      const acc = est.result(strategy);
      if (!acc) return;
      const i = acc.inputs.map((i) => i.witnessUtxo.amount);
      const o = acc.outputs.map((i) => i.amount);
      const tx = acc.tx;
      tx.sign(privKey1);
      tx.finalize();
      const expFee = BigInt(tx.vsize) * FEE;
      return {
        i,
        o,
        txFee: tx.fee,
        expFee,
        fee: acc.fee,
        change: acc.change,
      };
    };
    deepStrictEqual(t2('default', 100n), {
      i: [16777216n],
      o: [100n, 16776893n],
      txFee: 223n,
      expFee: 223n,
      fee: 223n,
      change: true,
    });
    deepStrictEqual(t2('accumSmallest', 64n), {
      i: [256n],
      o: [64n],
      txFee: 192n,
      expFee: 190n,
      fee: 191n,
      change: false,
    });
    deepStrictEqual(t2('accumSmallest', 65n), {
      i: [256n],
      o: [65n],
      txFee: 191n,
      expFee: 191n,
      fee: 191n,
      change: false,
    });
    deepStrictEqual(t2('all', 100n), {
      i: [
        256n,
        512n,
        1024n,
        2048n,
        4096n,
        8192n,
        16384n,
        32768n,
        65536n,
        131072n,
        262144n,
        524288n,
        1048576n,
        2097152n,
        4194304n,
        8388608n,
        16777216n,
      ],
      o: [100n, 33551453n],
      txFee: 2623n,
      expFee: 2616n,
      fee: 2623n,
      change: true,
    });
    deepStrictEqual(t2('all', 33551554n), {
      i: [
        256n,
        512n,
        1024n,
        2048n,
        4096n,
        8192n,
        16384n,
        32768n,
        65536n,
        131072n,
        262144n,
        524288n,
        1048576n,
        2097152n,
        4194304n,
        8388608n,
        16777216n,
      ],
      o: [33551554n],
      txFee: 2622n,
      expFee: 2583n,
      fee: 2591n,
      change: false,
    });
    deepStrictEqual(t2('all', 33551406n), {
      i: [
        256n,
        512n,
        1024n,
        2048n,
        4096n,
        8192n,
        16384n,
        32768n,
        65536n,
        131072n,
        262144n,
        524288n,
        1048576n,
        2097152n,
        4194304n,
        8388608n,
        16777216n,
      ],
      o: [33551406n],
      txFee: 2770n,
      expFee: 2580n,
      fee: 2591n,
      change: false,
    });
    deepStrictEqual(t2('all', 33551405n), {
      i: [
        256n,
        512n,
        1024n,
        2048n,
        4096n,
        8192n,
        16384n,
        32768n,
        65536n,
        131072n,
        262144n,
        524288n,
        1048576n,
        2097152n,
        4194304n,
        8388608n,
        16777216n,
      ],
      o: [33551405n],
      txFee: 2771n,
      expFee: 2580n,
      fee: 2591n,
      change: false,
    });

    const t3 = (strategy) => {
      const FEE = 0n // no fee to test exact amounts
      const est = new btc._Estimator(inputs, [{ ...OUTPUTS[0], amount: inputsTotalAmount }], {
        feePerByte: FEE,
        changeAddress: '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
        network: regtest,
        allowLegacyWitnessUtxo: true,
        createTx: true,
        allowSameUtxo: true,
      });
      const acc = est.result(strategy);
      if (!acc) return;
      const i = acc.inputs.map((i) => i.witnessUtxo.amount);
      const o = acc.outputs.map((i) => i.amount);
      const tx = acc.tx;
      tx.sign(privKey1);
      tx.finalize();
      const expFee = BigInt(tx.vsize) * FEE;
      return {
        i,
        o,
        txFee: tx.fee,
        expFee,
        fee: acc.fee,
        change: acc.change,
      };
    };
    deepStrictEqual(t3('default'), {
      i: inputs.map((i) => i.witnessUtxo.amount).reverse(),
      o: [inputsTotalAmount],
      txFee: 0n,
      expFee: 0n,
      fee: 0n,
      change: false,
    });
    deepStrictEqual(t3('accumSmallest'), {
      i: inputs.map((i) => i.witnessUtxo.amount),
      o: [inputsTotalAmount],
      txFee: 0n,
      expFee: 0n,
      fee: 0n,
      change: false,
    });
    deepStrictEqual(t3('all'), {
      i: inputs.map((i) => i.witnessUtxo.amount),
      o: [inputsTotalAmount],
      txFee: 0n,
      expFee: 0n,
      fee: 0n,
      change: false,
    });
  });

  should('bip69/inputs', () => {
    // from bip69
    const INP1 = [
      ['0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57', 0],
      ['26aa6e6d8b9e49bb0630aac301db6757c02e3619feb4ee0eea81eb1672947024', 1],
      ['28e0fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2', 0],
      ['381de9b9ae1a94d9c17f6a08ef9d341a5ce29e2e60c36a52d333ff6203e58d5d', 1],
      ['3b8b2f8efceb60ba78ca8bba206a137f14cb5ea4035e761ee204302d46b98de2', 0],
      ['402b2c02411720bf409eff60d05adad684f135838962823f3614cc657dd7bc0a', 1],
      ['54ffff182965ed0957dba1239c27164ace5a73c9b62a660c74b7b7f15ff61e7a', 1],
      ['643e5f4e66373a57251fb173151e838ccd27d279aca882997e005016bb53d5aa', 0],
      ['6c1d56f31b2de4bfc6aaea28396b333102b1f600da9c6d6149e96ca43f1102b1', 1],
      ['7a1de137cbafb5c70405455c49c5104ca3057a1f1243e6563bb9245c9c88c191', 0],
      ['7d037ceb2ee0dc03e82f17be7935d238b35d1deabf953a892a4507bfbeeb3ba4', 1],
      ['a5e899dddb28776ea9ddac0a502316d53a4a3fca607c72f66c470e0412e34086', 0],
      ['b4112b8f900a7ca0c8b0e7c4dfad35c6be5f6be46b3458974988e1cdb2fa61b8', 0],
      ['bafd65e3c7f3f9fdfdc1ddb026131b278c3be1af90a4a6ffa78c4658f9ec0c85', 0],
      ['de0411a1e97484a2804ff1dbde260ac19de841bebad1880c782941aca883b4e9', 1],
      ['f0a130a84912d03c1d284974f563c5949ac13f8342b8112edff52971599e6a45', 0],
      ['f320832a9d2e2452af63154bc687493484a0e7745ebd3aaf9ca19eb80834ad60', 0],
    ];
    const INP2 = [
      ['35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055', 0],
      ['35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055', 1],
    ];

    const tBasic = (inputs) => {
      const est = new btc._Estimator(
        inputs.map(([txId, index]) => ({
          txid: hex.decode(txId),
          index,
          witnessUtxo: { script: spend2_4.script, amount: 10n },
        })),
        [],
        {
          allowLegacyWitnessUtxo: true,
          feePerByte: 1n,
          changeAddress: '1KAD5EnzzLtrSo2Da2G4zzD7uZrjk8zRAv',
          allowSameUtxo: true,
        }
      );
      return est.sortIndices(inputs.map((_, i) => i));
    };

    const t = (inputs) => {
      const inp = Array.from(inputs).reverse();
      const o = tBasic(inp);
      deepStrictEqual(
        o.map((i) => inp[i]),
        inputs,
        inputs.map((_, i) => i).reverse()
      );
    };
    t(INP1);
    t(INP2);

    deepStrictEqual(
      tBasic([
        ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0],
        ['cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 0],
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 0],
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbff', 0],
        ['ffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 0],
      ]),
      [0, 2, 3, 1, 4]
    );
    deepStrictEqual(
      tBasic([
        ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1],
        ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 2],
        ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0],
      ]),
      [2, 0, 1]
    );
    deepStrictEqual(
      tBasic([
        ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 99],
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 99],
        ['cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 0],
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 0],
      ]),
      [0, 3, 1, 2]
    );
    deepStrictEqual(
      tBasic([
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 0],
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 1],
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 0],
        ['cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 1],
        ['cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 2],
      ]),
      [0, 2, 1, 3, 4]
    );

    // Outputs
    const est = new btc._Estimator([], [], {
      allowLegacyWitnessUtxo: true,
      feePerByte: 1n,
      allowUnknownOutputs: true,
      changeAddress: '1KAD5EnzzLtrSo2Da2G4zzD7uZrjk8zRAv',
    });

    deepStrictEqual(
      est.sortOutputs([
        {
          amount: 40_000_000_000n,
          script: hex.decode('76a9145be32612930b8323add2212a4ec03c1562084f8488ac'),
        },
        {
          amount: 400_057_456n,
          script: hex.decode('76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac'),
        },
      ]),
      [1, 0]
    );
    deepStrictEqual(
      est.sortOutputs([
        {
          amount: 40_000_000_000n,
          address: '19Nrc2Xm226xmSbeGZ1BVtX7DUm4oCx8Pm',
        },
        {
          amount: 400_057_456n,
          address: '17nFgS1YaDPnXKMPQkZVdNQqZnVqRgBwnZ',
        },
      ]),
      [1, 0]
    );
    deepStrictEqual(
      est.sortOutputs([
        { amount: 3_000n, script: hex.decode('00000000') },
        { amount: 2_000n, script: hex.decode('00000000') },
        { amount: 1_000n, script: hex.decode('00000000') },
      ]),
      [2, 1, 0]
    );
    deepStrictEqual(
      est.sortOutputs([
        {
          amount: 1n,
          script: hex.decode('76a9144a5fba237213a062f6f57978f796390bdcf8d01588ac'),
        },
        {
          amount: 1n,
          script: hex.decode('76a9145be32612930b8323add2212a4ec03c1562084f8488ac'),
        },
      ]),
      [0, 1]
    );
  });

  should('example', () => {
    const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
    const pubKey = secp256k1.getPublicKey(privKey, true);
    const spend = btc.p2wpkh(pubKey, regtest);
    const utxo = [
      {
        ...spend, // add witness/redeem scripts from spend
        // Get txid, index from explorer/network
        txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
        index: 0,
        // utxo tx information
        // script can be used from spend itself or from explorer
        witnessUtxo: { script: spend.script, amount: 100_000n }, // value in satoshi
      },
      {
        ...spend,
        txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
        index: 1,
        witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') }, // value in btc
      },
      // {
      //   ...spend,
      //   txid: hex.decode('75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858'),
      //   index: 0,
      //   // tx hex from blockchain (required for non-SegWit UTXO)
      //   nonWitnessUtxo: hex.decode(
      //     '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000'
      //   ),
      // },
    ];
    const outputs = [
      { address: '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3', amount: 50_000n }, // amount in satoshi
      {
        address: 'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm',
        amount: btc.Decimal.decode('0.5'), // amount in btc
      },
    ];
    // Send all utxo to specific address (consolidation):
    // const selected = btc.selectUTXO(utxo, [], 'all', {
    //   changeAddress: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8', ...
    const selected = btc.selectUTXO(utxo, outputs, 'default', {
      changeAddress: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8', // required, address to send change
      feePerByte: 2n, // require, fee per vbyte in satoshi
      bip69: true, // lexicographical Indexing of Transaction Inputs and Outputs
      createTx: true, // create tx with selected inputs/outputs
      network: regtest,
    });
    // 'selected' will 'undefined' if there is not enough funds
    deepStrictEqual(selected.fee, 394n); // estimated fee
    deepStrictEqual(selected.change, true); // change address used
    deepStrictEqual(selected.outputs, [
      { address: '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3', amount: 50000n },
      {
        address: 'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm',
        amount: 50_000_000n,
      },
      // Change address
      // with bip69 it is not neccesarily last item in outputs
      {
        address: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
        amount: 99_949_606n,
      },
    ]);
    // No need to create tx manually!
    const { tx } = selected;
    tx.sign(privKey);
    tx.finalize();
    deepStrictEqual(tx.id, 'b702078d65edd65a84b2a97a669df5631b06f42a67b0d7090e540b02cc65aed5');
    // real tx fee, can be bigger than estimated, since we expect signatures of maximal size
    deepStrictEqual(tx.fee, 394n);
  });
  should('requiredInputs', () => {
    const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
    const pubKey = secp256k1.getPublicKey(privKey, true);
    const spend = btc.p2wpkh(pubKey, regtest);
    const txid = hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2');
    const utxo = [
      {
        ...spend,
        txid,
        index: 0,
        witnessUtxo: { script: spend.script, amount: 100_000n },
      },
      {
        ...spend,
        txid,
        index: 1,
        witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') }, // value in btc
      },
    ];
    const requiredSmall = [
      {
        ...spend,
        txid,
        index: 99,
        witnessUtxo: { script: spend.script, amount: 100_000n },
      },
    ];
    const requiredBig = [
      {
        ...spend,
        txid,
        index: 99,
        witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('2.5') },
      },
    ];
    const outputs = [
      { address: '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3', amount: 50_000n }, // amount in satoshi
      {
        address: 'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm',
        amount: btc.Decimal.decode('0.5'), // amount in btc
      },
    ];
    // Big input covers everything, no need for others
    const selectedBig = btc.selectUTXO(utxo, outputs, 'default', {
      changeAddress: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8', // required, address to send change
      feePerByte: 2n, // require, fee per vbyte in satoshi
      bip69: true, // lexicographical Indexing of Transaction Inputs and Outputs
      createTx: true, // create tx with selected inputs/outputs
      network: regtest,
      requiredInputs: requiredBig,
    });
    deepStrictEqual(selectedBig.inputs, [
      {
        txid,
        index: 99,
        witnessUtxo: { script: spend.script, amount: 250000000n },
        sequence: 4294967295,
      },
    ]);
    deepStrictEqual(selectedBig.outputs, [
      { address: '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3', amount: 50000n },
      {
        address: 'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm',
        amount: 50_000_000n,
      },
      {
        address: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
        amount: 199_949_606n,
      },
    ]);
    // This covered by 1.5btc input, but we force add required input anyway
    const selectedSmall = btc.selectUTXO(utxo, outputs, 'default', {
      changeAddress: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8', // required, address to send change
      feePerByte: 2n, // require, fee per vbyte in satoshi
      bip69: true, // lexicographical Indexing of Transaction Inputs and Outputs
      createTx: true, // create tx with selected inputs/outputs
      network: regtest,
      requiredInputs: requiredSmall,
    });
    deepStrictEqual(selectedSmall.inputs, [
      {
        txid,
        index: 1,
        witnessUtxo: { script: spend.script, amount: 150000000n },
        sequence: 4294967295,
      },
      {
        txid,
        index: 99,
        witnessUtxo: { script: spend.script, amount: 100000n },
        sequence: 4294967295,
      },
    ]);
    deepStrictEqual(selectedSmall.outputs, [
      { address: '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3', amount: 50000n },
      {
        address: 'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm',
        amount: 50_000_000n,
      },
      {
        address: 'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
        amount: 100_049_470n,
      },
    ]);
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

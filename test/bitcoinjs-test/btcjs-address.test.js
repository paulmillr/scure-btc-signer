import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { hex, base64 } from '@scure/base';
import * as btc from '../../index.js';
import { default as p2ms } from './fixtures/bitcoinjs/p2ms.json' assert { type: 'json' };
import { default as p2pk } from './fixtures/bitcoinjs/p2pk.json' assert { type: 'json' };
import { default as p2pkh } from './fixtures/bitcoinjs/p2pkh.json' assert { type: 'json' };
import { default as p2sh } from './fixtures/bitcoinjs/p2sh.json' assert { type: 'json' };
import { default as p2wpkh } from './fixtures/bitcoinjs/p2wpkh.json' assert { type: 'json' };
import { default as p2wsh } from './fixtures/bitcoinjs/p2wsh.json' assert { type: 'json' };
import { default as p2tr } from './fixtures/bitcoinjs-taproot/p2tr.json' assert { type: 'json' };
import { default as p2tr_ns } from './fixtures/bitcoinjs-taproot/p2tr_ns.json' assert { type: 'json' };
import { default as p2tr_bitgo } from './fixtures/bitcoinjs-taproot/p2tr_bitgo.json' assert { type: 'json' };

import * as utils from './utils.js';

const typeMap = {
  pk: 'p2pk',
  pkh: 'p2pkh',
  sh: 'p2sh',
  wpkh: 'p2wpkh',
  wsh: 'p2wsh',
  ms: 'p2ms',
  tr: 'p2tr',
  tr_ns: 'p2tr_ns',
};

const payments = { p2ms, p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, p2tr_bitgo, p2tr_ns };
for (const type in payments) {
  const payment = payments[type];
  //console.log('K', Object.keys(payment));
  for (let i = 0; i < payment.valid.length; i++) {
    const t = payment.valid[i];
    const realType = type.replace('_bitgo', '');
    should(`format: ${type}(${i}): ${t.description}`, () => {
      if (t.expected.address && t.expected.output) {
        const address = t.expected.address;
        const script = btc.Script.encode(utils.fromASM(t.expected.output));
        const net = utils.getNet(t.expected.network || t.arguments.network);
        const addr = btc.Address(net);
        const outScript = btc.OutScript.encode(addr.decode(address));
        deepStrictEqual(outScript, script);
        const parsedScript = btc.OutScript.decode(script);
        deepStrictEqual(btc.OutScript.encode(parsedScript), script);
        const parsedType = typeMap[parsedScript.type];
        deepStrictEqual(parsedType, realType);
        deepStrictEqual(addr.encode(parsedScript), address);
      } else if (t.expected.output) {
        const script = btc.Script.encode(utils.fromASM(t.expected.output));
        if (type === 'p2tr_ns' && !t.expected.output.endsWith('CHECKSIG')) return;
        const parsedScript = btc.OutScript.decode(script);
        deepStrictEqual(btc.OutScript.encode(parsedScript), script);
        const parsedType = typeMap[parsedScript.type];
        deepStrictEqual(parsedType, realType);
      }
    });
  }
}

// Old tests
const types = {
  p2pkh: btc.p2pkh,
  p2sh: btc.p2sh,
  p2wsh: btc.p2wsh,
  p2wpkh: btc.p2wpkh,
  p2ms: btc.p2ms,
};
for (const type in payments) {
  const payment = payments[type];
  if (!types[type]) continue;
  for (let i = 0; i < payment.valid.length; i++) {
    const v = payment.valid[i];
    should(`format(1): ${type}(${i}): ${v.description}`, () => {
      if (type === 'p2tr') return;
      if (v.arguments.pubkey) {
        deepStrictEqual(types[type](hex.decode(v.arguments.pubkey)).address, v.expected.address);
      }
      if (type === 'p2ms' && v.arguments.m && v.arguments.pubkeys) {
        const out = hex.encode(btc.Script.encode(utils.fromASM(v.expected.output)));
        const pubkeys = v.arguments.pubkeys.map(hex.decode);
        deepStrictEqual(hex.encode(types.p2ms(v.arguments.m, pubkeys).script), out);
      }
    });
  }
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import { hex, utf8 } from '@scure/base';
import * as btc from '../lib/esm/index.js';
import * as ordinals from '../lib/esm/ordinals.js';
import * as utils from '../lib/esm/utils.js';
import { schnorr as secp256k1_schnorr } from '@noble/curves/secp256k1';
import { default as ordvectors } from './fixtures/ordinals.json' assert { type: 'json' };

// The file misses a bunch of valid test vectors for inscriptions.
// There are only a few official test vectors.
// We collect transactions with specific features manually.
// It is complicated: there are no filters.
// TODO: add more test vectors.

describe('Ordinals', () => {
  describe('Tags', () => {
    should('pointer', () => {
      const pointer = ordinals.__test__.TagCoders.pointer;
      deepStrictEqual(pointer.decode(hex.decode('ff')), 255n);
      deepStrictEqual(pointer.decode(hex.decode('0001')), 256n);
      deepStrictEqual(pointer.decode(hex.decode('000100')), 256n);
    });
    should('InscriptionId', () => {
      const VECTORS = [
        [
          '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100',
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fi0',
        ],
        [
          '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100ff',
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fi255',
        ],
        [
          '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201000001',
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fi256',
        ],
      ];
      for (const [raw, exp] of VECTORS) {
        deepStrictEqual(ordinals.InscriptionId.decode(hex.decode(raw)), exp);
        deepStrictEqual(ordinals.InscriptionId.encode(exp), hex.decode(raw));
      }
    });
    should('rune', () => {
      const rune = ordinals.__test__.TagCoders.rune;
      const VECTORS = [
        [0n, []],
        [1n, [1]],
        [255n, [255]],
        [256n, [0, 1]],
        [65535n, [255, 255]],
        [65536n, [0, 0, 1]],
        [340_282_366_920_938_463_463_374_607_431_768_211_455n, new Array(16).fill(255)],
      ];
      for (const [exp, raw] of VECTORS) {
        deepStrictEqual(rune.decode(new Uint8Array(raw)), exp);
        deepStrictEqual(rune.encode(exp), new Uint8Array(raw));
      }
    });
    should('multiple parents', () => {
      const vector = [
        '027360480f9532e84cff10d53f06663e5e24aab0817ba4f022dda288df74bf3ci0',
        '73aa7ab6edaaf6113f1346c98566f945132cf40df4224c4d3f7568d4daf4d60ci0',
      ];
      const { TagCoder } = ordinals.__test__;
      deepStrictEqual(TagCoder.encode(TagCoder.decode({ parent: vector })), { parent: vector });
    });
  });

  should('inscription/11820782', () => {
    // https://ordiscan.com/inscription/11820782
    const rawTx = ordvectors[0].raw_tx;
    const tx = btc.Transaction.fromRaw(hex.decode(rawTx));
    const witness = tx.inputs[0].finalScriptWitness;
    const script = btc.Script.decode(witness[1]);
    // Not cursed, but strange script with DROP.
    // This is valid inscription, but too complex script
    deepStrictEqual(ordinals.OutOrdinalReveal.decode(script), undefined);
    deepStrictEqual(ordinals.parseInscriptions(script), [
      {
        tags: { contentType: 'image/svg+xml' },
        body: hex.decode(ordvectors[0].body),
        cursed: false,
      },
    ]);
  });

  should('inscription/62115659', () => {
    // 664655e657046ffcc4ea5e6116ae51abb0922f0efa6be399baeb759e898ae6a0
    // https://ordiscan.com/inscription/62115659
    const rawTx = ordvectors[1].raw_tx;

    const tx = btc.Transaction.fromRaw(hex.decode(rawTx));
    const witness = tx.inputs[0].finalScriptWitness;
    const script = btc.Script.decode(witness[1]);
    const encoded = ordinals.OutOrdinalReveal.encode(script);
    const newScript = btc.Script.encode(ordinals.OutOrdinalReveal.decode(encoded));
    deepStrictEqual(ordinals.OutOrdinalReveal.decode(encoded), script);
    deepStrictEqual(
      ordinals.OutOrdinalReveal.encode(btc.Script.decode(newScript)),
      ordinals.OutOrdinalReveal.encode(btc.Script.decode(witness[1]))
    );
    deepStrictEqual(newScript, witness[1]);
  });

  should('inscription/-471084', () => {
    // 26f6901cc730eb0d2da547d34d1251008030090b574193dd0100b73ca6c23220
    // CBOR, complex
    // https://ordiscan.com/inscription/-471084
    // parent: https://ordiscan.com/inscription/7523
    const rawTx = ordvectors[2].raw_tx;
    const tx = btc.Transaction.fromRaw(hex.decode(rawTx));
    const witness = tx.inputs[1].finalScriptWitness;
    const script = btc.Script.decode(witness[1]);
    const encoded = ordinals.OutOrdinalReveal.encode(script);
    const newScript = btc.Script.encode(ordinals.OutOrdinalReveal.decode(encoded));

    deepStrictEqual(ordinals.OutOrdinalReveal.decode(encoded), script);
    deepStrictEqual(
      ordinals.OutOrdinalReveal.encode(btc.Script.decode(newScript)),
      ordinals.OutOrdinalReveal.encode(btc.Script.decode(witness[1]))
    );
    deepStrictEqual(newScript, witness[1]);
  });

  should('CBRC', () => {
    // 49cbc5cbac92cf917dd4539d62720a3e528d17e22ef5fc47070a17ec0d3cf307
    // https://ordiscan.com/inscription/48315131
    const vector = ordvectors[3];
    const rawTx = vector.raw_tx;
    const tx = btc.Transaction.fromRaw(hex.decode(rawTx));
    const witness = tx.inputs[0].finalScriptWitness;
    const script = btc.Script.decode(witness[1]);
    const encoded = ordinals.OutOrdinalReveal.encode(script);
    deepStrictEqual(encoded, {
      type: 'tr_ord_reveal',
      pubkey: hex.decode(vector.pubkey),
      inscriptions: [
        {
          tags: vector.tags,
          body: hex.decode(vector.body),
          cursed: false,
        },
      ],
    });

    const newScript = btc.Script.encode(ordinals.OutOrdinalReveal.decode(encoded));
    deepStrictEqual(ordinals.OutOrdinalReveal.decode(encoded), script);
    deepStrictEqual(
      ordinals.OutOrdinalReveal.encode(btc.Script.decode(newScript)),
      ordinals.OutOrdinalReveal.encode(btc.Script.decode(witness[1]))
    );
    deepStrictEqual(newScript, witness[1]);
  });
  should('multiple parents', () => {
    // f988fe4b414a3f3d4a815dd1b1675dea0ba6140b1d698d8970273c781fb95746
    // https://ordiscan.com/inscription/-381350
    const vector = ordvectors[4];
    const rawTx = vector.raw_tx;
    const tx = btc.Transaction.fromRaw(hex.decode(rawTx));
    const witness = tx.inputs[0].finalScriptWitness;
    const script = btc.Script.decode(witness[1]);
    // We cannot encode/decode cursed using OutOrdinalReveal
    deepStrictEqual(ordinals.OutOrdinalReveal.decode(script), undefined);
    deepStrictEqual(ordinals.parseInscriptions(script), [
      {
        tags: vector.tags,
        body: hex.decode(vector.body),
        cursed: true,
      },
    ]);
  });

  describe('Parsing', () => {
    const { parseEnvelopes } = ordinals.__test__;
    should('checksig before', () => {
      deepStrictEqual(
        parseEnvelopes(
          btc.Script.decode(
            hex.decode(
              'ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800036f726468'
            )
          )
        ),
        [
          {
            start: 4,
            end: 8,
            pushnum: false,
            payload: [
              new Uint8Array([1]),
              new Uint8Array([
                116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 99, 104, 97, 114, 115, 101, 116,
                61, 117, 116, 102, 45, 56,
              ]),
              0,
              new Uint8Array([111, 114, 100]),
            ],
            stutter: false,
          },
        ]
      );
    });
    should('checksig after', () => {
      deepStrictEqual(
        parseEnvelopes(
          btc.Script.decode(
            hex.decode(
              '0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800036f726468ac'
            )
          )
        ),
        [
          {
            start: 3,
            end: 7,
            pushnum: false,
            payload: [
              new Uint8Array([1]),
              new Uint8Array([
                116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 99, 104, 97, 114, 115, 101, 116,
                61, 117, 116, 102, 45, 56,
              ]),
              0,
              new Uint8Array([111, 114, 100]),
            ],
            stutter: false,
          },
        ]
      );
    });

    should('multiple', () => {
      deepStrictEqual(
        parseEnvelopes(
          btc.Script.decode(
            hex.decode(
              '0063036f7264010118746578742f706c61696e3b636861727365743d7574662d380003666f6f680063036f7264010118746578742f706c61696e3b636861727365743d7574662d38000362617268'
            )
          )
        ),
        [
          {
            start: 3,
            end: 7,
            pushnum: false,
            payload: [
              new Uint8Array([1]),
              new Uint8Array([
                116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 99, 104, 97, 114, 115, 101, 116,
                61, 117, 116, 102, 45, 56,
              ]),
              0,
              new Uint8Array([102, 111, 111]),
            ],
            stutter: false,
          },
          {
            start: 11,
            end: 15,
            pushnum: false,
            payload: [
              new Uint8Array([1]),
              new Uint8Array([
                116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 99, 104, 97, 114, 115, 101, 116,
                61, 117, 116, 102, 45, 56,
              ]),
              0,
              new Uint8Array([98, 97, 114]),
            ],
            stutter: false,
          },
        ]
      );
    });
    should('no endif', () => {
      deepStrictEqual(parseEnvelopes(btc.Script.decode(hex.decode('0063036f7264'))), []);
    });
    should('no 0', () => {
      deepStrictEqual(parseEnvelopes(btc.Script.decode(hex.decode('63036f726468'))), []);
    });
    should('second envelope', () => {
      const script = hex.decode(
        '0063036f7264010103666f6f004c6401010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101680063036f7264010103626172004c640101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010168'
      );
      deepStrictEqual(parseEnvelopes(btc.Script.decode(script)), [
        {
          start: 3,
          end: 7,
          pushnum: false,
          payload: [
            new Uint8Array([1]),
            new Uint8Array([102, 111, 111]),
            0,
            new Uint8Array([
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            ]),
          ],
          stutter: false,
        },
        {
          start: 11,
          end: 15,
          pushnum: false,
          payload: [
            new Uint8Array([1]),
            new Uint8Array([98, 97, 114]),
            0,
            new Uint8Array([
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            ]),
          ],
          stutter: false,
        },
      ]);
    });
    should('PushNum', () => {
      const VECTORS = [
        ['0063036f7264004f68', new Uint8Array([129])],
        ['0063036f7264005168', new Uint8Array([1])],
        ['0063036f7264005268', new Uint8Array([2])],
        ['0063036f7264005368', new Uint8Array([3])],
        ['0063036f7264005468', new Uint8Array([4])],
        ['0063036f7264005568', new Uint8Array([5])],
        ['0063036f7264005668', new Uint8Array([6])],
        ['0063036f7264005768', new Uint8Array([7])],
        ['0063036f7264005868', new Uint8Array([8])],
        ['0063036f7264005968', new Uint8Array([9])],
        ['0063036f7264005a68', new Uint8Array([10])],
        ['0063036f7264005b68', new Uint8Array([11])],
        ['0063036f7264005c68', new Uint8Array([12])],
        ['0063036f7264005d68', new Uint8Array([13])],
        ['0063036f7264005e68', new Uint8Array([14])],
        ['0063036f7264005f68', new Uint8Array([15])],
        ['0063036f7264006068', new Uint8Array([16])],
      ];
      for (const [scriptHex, exp] of VECTORS) {
        const res = parseEnvelopes(btc.Script.decode(hex.decode(scriptHex)));
        deepStrictEqual(res[0].pushnum, true);
        deepStrictEqual(res[0].payload, [0, exp]);
      }
    });
    should('stutter', () => {
      // 0 0 IF PROTOCOL_ID ENDIF
      deepStrictEqual(parseEnvelopes(btc.Script.decode(hex.decode('000063036f726468'))), [
        {
          start: 4,
          end: 4,
          payload: [],
          pushnum: false,
          stutter: true,
        },
      ]);
      // 0 IF 0 IF PROTOCOL_ID ENDIF
      deepStrictEqual(parseEnvelopes(btc.Script.decode(hex.decode('00630063036f726468'))), [
        {
          start: 5,
          end: 5,
          payload: [],
          pushnum: false,
          stutter: true,
        },
      ]);
      // 0 IF 0 IF 0 IF PROTOCOL_ID ENDIF
      deepStrictEqual(parseEnvelopes(btc.Script.decode(hex.decode('006300630063036f726468'))), [
        {
          start: 7,
          end: 7,
          payload: [],
          pushnum: false,
          stutter: true,
        },
      ]);
      // 0 0 AND 0 IF PROTOCOL_ID ENDIF
      deepStrictEqual(parseEnvelopes(btc.Script.decode(hex.decode('0000840063036f726468'))), [
        {
          start: 6,
          end: 6,
          payload: [],
          pushnum: false,
          stutter: true,
        },
      ]);
    });
  });
  should('unknown fields', () => {
    const t = btc.Script.decode(new Uint8Array([0, 99, 3, 111, 114, 100, 1, 255, 1, 0, 104]));
    deepStrictEqual(ordinals.parseInscriptions(t), [
      {
        body: new Uint8Array([]),
        cursed: false,
        tags: { unknown: [[new Uint8Array([255]), new Uint8Array([0])]] },
      },
    ]);
    deepStrictEqual(
      ordinals.OutOrdinalReveal.decode({
        type: 'tr_ord_reveal',
        pubkey: new Uint8Array(32),
        inscriptions: [
          {
            tags: { unknown: [[new Uint8Array([255]), new Uint8Array([0])]] },
            body: new Uint8Array([]),
          },
        ],
      }),
      [
        new Uint8Array(32),
        'CHECKSIG',
        0,
        'IF',
        new Uint8Array([111, 114, 100]),
        new Uint8Array([255]),
        new Uint8Array([0]),
        0,
        'ENDIF',
      ]
    );
  });
  should('Example (fake)', () => {
    /*
    Wallet: https://sparrowwallet.com
    - open /Applications/Sparrow.app --args -n testnet

    Testnet faucets:
    - https://bitcoinfaucet.uo1.net/send.php
    - https://coinfaucet.eu/en/btc-testnet/
    - https://cryptopump.info/send.php

    Explorer:
    - https://mempool.space/testnet
    - https://testnet-explorer.ordinalsbot.com ordinals
    */
    const TESTNET = utils.TEST_NETWORK;
    const privKey = hex.decode('0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a');
    const pubKey = secp256k1_schnorr.getPublicKey(privKey);
    // We need this to enable custom scripts outside
    const customScripts = [ordinals.OutOrdinalReveal];

    // This inscribes on first satoshi of first input (default)
    const inscription = {
      tags: {
        // can be any format (MIME type)
        // contentType: 'application/x-javascript',
        // contentType: 'text/html',
        contentType: 'application/json',
        // compression: only brotli supported
        // ContentEncoding: 'br', // brotli
      },
      body: utf8.decode(JSON.stringify({ some: 1, test: 2, inscription: true, in: 'json' })),
      // we can use previously inscribed js scripts in html
      // body: utf8.decode(
      //   `<html><head></head><body><script src="/content/script_inscription_id"></script>test</html>`
    };

    const revealPayment = btc.p2tr(
      undefined,
      ordinals.p2tr_ord_reveal(pubKey, [inscription]),
      TESTNET,
      false,
      customScripts
    );

    // We need to send some bitcoins to this address before reveal. Also, there should be enough
    // to cover reveal tx fee.
    console.log('ADDRESS', revealPayment.address);

    deepStrictEqual(
      revealPayment.address,
      'tb1p5mykwcq5ly7y2ctph9r2wfgldq94eccm2t83dd58k785p0zqzwkspyjkp5'
    );

    // You need to be extra careful with these, since it is possible to accidentally send
    // inscription as fee.
    // Also, rarity is only available with ordinal wallet. But you can parse
    // other inscriptions and create common one using this.
    const changeAddr = revealPayment.address; // can be different
    const revealAmount = 2000n;
    const fee = 500n;

    const tx = new btc.Transaction({ customScripts });
    tx.addInput({
      ...revealPayment,
      // This is txid of tx with bitcoins we sent (replace)
      txid: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
      index: 0,
      witnessUtxo: { script: revealPayment.script, amount: revealAmount },
    });
    tx.addOutputAddress(changeAddr, revealAmount - fee, TESTNET);
    tx.sign(privKey, undefined, new Uint8Array(32));
    tx.finalize();

    const txHex = hex.encode(tx.extract());

    // Hex of reveal tx to broadcast
    deepStrictEqual(
      txHex,
      '0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff01dc05000000000000225120a6c9676014f93c456161b946a7251f680b5ce31b52cf16b687b78f40bc4013ad03400e0888a69181fb2745c81cb595bdc1966e8b974a1c06b944e5f2be655af01fe5e1cc9626d6a97041a4b18654e20f7bd88a6ab1d12f6518b03264a19493946a7e7020f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac0063036f72640101106170706c69636174696f6e2f6a736f6e00327b22736f6d65223a312c2274657374223a322c22696e736372697074696f6e223a747275652c22696e223a226a736f6e227d6821c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac000000000'
    );
    // Parsing inscriptions
    // console.log('HEX', txHex);
    const tx2 = btc.Transaction.fromRaw(hex.decode(txHex));
    // console.log('PARSED', ordinals.parseWitness(tx2.inputs[0].finalScriptWitness));
    // Reveal tx should pay at least this much fee
    // console.log('VSIZE', tx2.vsize);
  });
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

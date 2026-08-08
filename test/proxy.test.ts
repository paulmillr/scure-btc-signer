import { it } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import * as mftch from 'micro-ftch';
import { deepStrictEqual } from 'node:assert';
import * as net from 'node:net';
import { EsploraProvider, type TransfersOpts } from '../src/net.ts';
import { Address, OutScript, p2wpkh } from '../src/payment.ts';
import { RawTx } from '../src/script.ts';
import { Transaction } from '../src/transaction.ts';
import { pubECDSA, sha256 } from '../src/utils.ts';
import { startProxy } from './misc/proxy.ts';
import { default as NET_BASIC } from './vectors/rpc/net_basic.js';

const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
const priv = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
const otherPriv = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
const addr = p2wpkh(pubECDSA(priv, true), regtest).address!;
const other = p2wpkh(pubECDSA(otherPriv, true), regtest).address!;
const script = OutScript.encode(Address(regtest).decode(addr));
const otherScript = OutScript.encode(Address(regtest).decode(other));
const NODE_URL = 'https://NODE_URL';
const LIVE_URL = process.env.ESPLORA_URL;
const LIVE_ELECTRUM = process.env.SCURE_BTC_ELECTRUM_URL;
const TAPROOT_ADDR = 'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5';
const TAPROOT_TX = 'f5d1f75e2f3fcc0afe3210d3ef9b5bde67b6e41bb3be2de3cd4e779c1a92c1f3';
const TAPROOT_RAW =
  '020000000001012a902eca16d6af2ab7d08b63b810b58b0bea33853f55cd3ce1f52edf4194ed7e0400000000feffffff020f2700000000000022512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda3433a4d040000000000160014580b5fd1ef93ad3a5ecac248e1f719dc719a9e9602473044022056db5086d85e669fc8713c376f6e3bb3e8f6d7ee39e7a59792985ee07d9462e202204870556d23909d6adf7b0b9036ddf694a36a73a191d098cdc00e30aac67c36830121028a1b8c1abc60dfc9586903e599d03730a07c0a5aab37e18ace923b1f65e5d062bb050b00';
const UNSPENT_ADDR = '18qZ8FJho16xzNqQrPouobhyH4hf4uqZrj';
const OLD_ADDR = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const PAGE_CURSOR_FIRST = '5c448fc9f4101f99c063f956bbac6394fc497684e2844ec448461d4c391eba08';
const PAGE_CURSOR_LATER = '7231e3eefa4154600f0a2cf75384d0c02c0f34620850b3c7f48a157fb7198e75';
const PAGE_CASES: [string, TransfersOpts][] = [
  ['limit', { limit: 7 }],
  ['fromBlock', { fromBlock: 914_000 }],
  ['fromBlock+limit', { fromBlock: 914_000, limit: 5 }],
  ['toBlock', { toBlock: 511_603 }],
  ['toBlock+limit', { toBlock: 754_111, limit: 5 }],
  ['fromBlock+toBlock', { fromBlock: 507_209, toBlock: 511_603 }],
  ['fromBlock+toBlock+limit', { fromBlock: 497_677, toBlock: 754_111, limit: 4 }],
  ['afterTxid', { afterTxid: PAGE_CURSOR_LATER }],
  ['afterTxid+limit', { afterTxid: PAGE_CURSOR_FIRST, limit: 6 }],
];
const getKey = (url: string, opt: mftch.FetchOpts) =>
  JSON.stringify({ url: `${NODE_URL}${new URL(url).pathname}`, opt });
type Req = { id: number; method: string; params: unknown[] };

const u32 = (value: number): Uint8Array =>
  new Uint8Array([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, value >>> 24]);
const reverse = (value: Uint8Array): Uint8Array => Uint8Array.from(value).reverse();
const reverseTxid = (txid: string): string => txid.match(/../g)!.reverse().join('');
const headerHash = (header: Uint8Array): string => hex.encode(reverse(sha256(sha256(header))));
const blockHeader = (opts: {
  version: number;
  parent: string;
  merkleRoot: string;
  timestamp: number;
  bits: number;
  nonce: number;
}) => {
  const res = new Uint8Array(80);
  res.set(u32(opts.version), 0);
  res.set(reverse(hex.decode(opts.parent)), 4);
  res.set(reverse(hex.decode(opts.merkleRoot)), 36);
  res.set(u32(opts.timestamp), 68);
  res.set(u32(opts.bits), 72);
  res.set(u32(opts.nonce), 76);
  return { raw: res, hex: hex.encode(res), hash: headerHash(res) };
};

const txRaw = (
  inputs: { txid: Uint8Array; index: number }[],
  outputs: { amount: bigint; script: Uint8Array }[]
) => {
  const raw = RawTx.encode({
    version: 2,
    segwitFlag: false,
    inputs: inputs.map((input) => ({
      txid: input.txid,
      index: input.index,
      finalScriptSig: new Uint8Array([1]),
      sequence: 0xffffffff,
    })),
    outputs,
    lockTime: 0,
  });
  return {
    raw,
    hex: hex.encode(raw),
    // Proxy fixtures include value-only OP_RETURN-style outputs; txid derivation must not reject them.
    txid: Transaction.fromRaw(raw, { allowUnknownInputs: true, allowUnknownOutputs: true }).id,
  };
};

const fakeElectrum = async (handler: (req: Req) => unknown | Promise<unknown>) => {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.setEncoding('utf8');
    let buf = '';
    socket.on('data', (chunk) => {
      buf += chunk;
      for (;;) {
        const pos = buf.indexOf('\n');
        if (pos < 0) break;
        const line = buf.slice(0, pos).trim();
        buf = buf.slice(pos + 1);
        if (!line) continue;
        const req = JSON.parse(line) as Req;
        Promise.resolve(handler(req)).then(
          (result) => socket.write(`${JSON.stringify({ id: req.id, result })}\n`),
          (err) =>
            socket.write(
              `${JSON.stringify({ id: req.id, error: { message: String(err.message || err) } })}\n`
            )
        );
      }
    });
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const info = server.address();
  if (!info || typeof info !== 'object') throw new Error('expected fake Electrum TCP address');
  return {
    url: `tcp://127.0.0.1:${info.port}`,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );
    },
  };
};

it('test/proxy: serves Esplora-shaped HTTP over Electrum TCP', async () => {
  const header = blockHeader({
    version: 0x20000000,
    parent: '11'.repeat(32),
    merkleRoot: '22'.repeat(32),
    timestamp: 1710000321,
    bits: 0x1d00ffff,
    nonce: 42,
  });
  const parent = txRaw(
    [{ txid: new Uint8Array(32), index: 0xffffffff }],
    [{ amount: 6000n, script }]
  );
  const child = txRaw(
    [{ txid: hex.decode(parent.txid), index: 0 }],
    [
      { amount: 4000n, script: otherScript },
      { amount: 1860n, script: new Uint8Array([0x6a]) },
    ]
  );
  const electrum = await fakeElectrum((req) => {
    const [a, b] = req.params;
    if (req.method === 'blockchain.headers.subscribe') return { height: 321 };
    if (req.method === 'blockchain.block.header' && a === 321) return header.hex;
    if (req.method === 'blockchain.block.header' && typeof a === 'number')
      return blockHeader({
        version: 0x20000000,
        parent: '11'.repeat(32),
        merkleRoot: '22'.repeat(32),
        timestamp: 1710000321,
        bits: 0x1d00ffff,
        nonce: a,
      }).hex;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 321 && b === 0)
      return { tx_hash: child.txid };
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 321)
      return Promise.reject(new Error(`No tx in position #${b} in block #321`));
    if (req.method === 'blockchain.estimatefee') return 0.000021;
    if (req.method === 'blockchain.scripthash.get_history')
      return [{ tx_hash: child.txid, height: 105 }];
    if (req.method === 'blockchain.scripthash.listunspent')
      return [{ tx_hash: parent.txid, tx_pos: 0, height: 7, value: 6000 }];
    // Electrum returns the txid on successful broadcast; provider tests validate that contract.
    if (req.method === 'blockchain.transaction.broadcast') return child.txid;
    if (req.method === 'blockchain.transaction.get') {
      const raw = a === child.txid ? child : parent;
      if (b) return { hex: raw.hex, blockhash: header.hash, time: 1710000000, confirmations: 1 };
      return raw.hex;
    }
    return Promise.reject(new Error(`unexpected method ${req.method}`));
  });
  const proxy = await startProxy({
    electrum: electrum.url,
    listen: '127.0.0.1:0',
    network: regtest,
  });
  try {
    const height = await fetch(`${proxy.url}/blocks/tip/height`);
    deepStrictEqual(
      {
        status: height.status,
        cors: height.headers.get('access-control-allow-origin'),
        methods: height.headers.get('access-control-allow-methods'),
        headers: height.headers.get('access-control-allow-headers'),
        body: await height.text(),
      },
      {
        status: 200,
        cors: '*',
        methods: 'GET, POST, OPTIONS',
        headers: 'Content-Type',
        body: '321',
      }
    );
    const preflight = await fetch(proxy.url, { method: 'OPTIONS' });
    deepStrictEqual(
      {
        status: preflight.status,
        cors: preflight.headers.get('access-control-allow-origin'),
        methods: preflight.headers.get('access-control-allow-methods'),
        headers: preflight.headers.get('access-control-allow-headers'),
        body: await preflight.text(),
      },
      {
        status: 204,
        cors: '*',
        methods: 'GET, POST, OPTIONS',
        headers: 'Content-Type',
        body: '',
      }
    );
    const provider = new EsploraProvider(fetch, proxy.url, regtest);
    deepStrictEqual(await provider.height(), 321);
    const directBlock = await fetch(`${proxy.url}/block/${header.hash}`);
    deepStrictEqual(
      { status: directBlock.status, body: await directBlock.json() },
      {
        status: 200,
        body: {
          id: header.hash,
          height: 321,
          version: 0x20000000,
          timestamp: 1710000321,
          size: 80 + 1 + child.raw.length,
          weight: 324 + child.raw.length * 4,
          merkle_root: '22'.repeat(32),
          previousblockhash: '11'.repeat(32),
          mediantime: 1710000321,
          nonce: 42,
          bits: 0x1d00ffff,
          difficulty: 1,
          tx_count: 1,
        },
      }
    );
    deepStrictEqual(await provider.blockInfo(321), {
      hash: header.hash,
      number: 321,
      version: 0x20000000,
      timestamp: 1710000321000,
      size: 80 + 1 + child.raw.length,
      weight: 324 + child.raw.length * 4,
      merkleRoot: '22'.repeat(32),
      parentHash: '11'.repeat(32),
      medianTime: 1710000321000,
      nonce: 42,
      bits: 0x1d00ffff,
      difficulty: 1,
      transactions: [child.txid],
    });
    deepStrictEqual(await provider.fee(2), 3n);
    deepStrictEqual(await provider.txCount(addr), 1);
    deepStrictEqual(await provider.sendTx(child.hex), child.txid);
    deepStrictEqual(await provider.unspent(addr), {
      symbol: 'BTC',
      decimals: 8,
      balance: 6000n,
      utxo: [{ txid: parent.txid, index: 0, nonWitnessUtxo: parent.raw }],
    });
    deepStrictEqual(await provider.transfers(addr), [
      {
        txid: child.txid,
        timestamp: 1710000000000,
        block: 105,
        transfers: [{ from: addr, value: 6000n }, { to: other, value: 4000n }, { value: 1860n }],
        info: {
          version: 2,
          lockTime: 0,
          size: child.raw.length,
          weight: child.raw.length * 4,
          fee: 140n,
          blockHash: header.hash,
          raw: child.hex,
        },
      },
    ]);
  } finally {
    await proxy.close();
    await electrum.close();
  }
});

it('test/proxy: preserves genesis block height on cached tx lookups', async () => {
  const header = blockHeader({
    version: 1,
    parent: '00'.repeat(32),
    merkleRoot: '33'.repeat(32),
    timestamp: 1710000000,
    bits: 0x1d00ffff,
    nonce: 0,
  });
  const coinbase = txRaw(
    [{ txid: new Uint8Array(32), index: 0xffffffff }],
    [{ amount: 5000000000n, script }]
  );
  const electrum = await fakeElectrum((req) => {
    const [a, b] = req.params;
    if (req.method === 'blockchain.headers.subscribe') return { height: 0 };
    if (req.method === 'blockchain.block.header' && a === 0) return header.hex;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 0 && b === 0)
      return coinbase.txid;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 0 && b === 1)
      return Promise.reject(new Error('No tx in position #1 in block #0'));
    if (req.method === 'blockchain.transaction.get' && a === coinbase.txid) {
      if (b)
        return { hex: coinbase.hex, blockhash: header.hash, time: 1710000000, confirmations: 1 };
      return coinbase.hex;
    }
    return Promise.reject(new Error(`unexpected method ${req.method}`));
  });
  const proxy = await startProxy({
    electrum: electrum.url,
    listen: '127.0.0.1:0',
    network: regtest,
  });
  try {
    const txids = await fetch(`${proxy.url}/block/${header.hash}/txids`);
    deepStrictEqual(await txids.json(), [coinbase.txid]);
    const tx = await fetch(`${proxy.url}/tx/${coinbase.txid}`);
    deepStrictEqual(await tx.json(), {
      txid: coinbase.txid,
      version: 2,
      locktime: 0,
      size: coinbase.raw.length,
      weight: coinbase.raw.length * 4,
      fee: 0,
      vin: [
        {
          txid: '00'.repeat(32),
          vout: 0xffffffff,
          scriptsig: '01',
          scriptsig_asm: 'OP_PUSHBYTES_1',
          sequence: 0xffffffff,
          is_coinbase: true,
        },
      ],
      vout: [
        {
          scriptpubkey: hex.encode(script),
          scriptpubkey_asm: 'OP_0 OP_PUSHBYTES_20 79b000887626b294a914501a4cd226b58b235983',
          scriptpubkey_type: 'v0_p2wpkh',
          scriptpubkey_address: addr,
          value: 5000000000,
        },
      ],
      status: {
        confirmed: true,
        block_height: 0,
        block_hash: header.hash,
        block_time: 1710000000,
      },
    });
  } finally {
    await proxy.close();
    await electrum.close();
  }
});

it('test/proxy: propagates unexpected block txid enumeration errors', async () => {
  const header = blockHeader({
    version: 0x20000000,
    parent: '11'.repeat(32),
    merkleRoot: '22'.repeat(32),
    timestamp: 1710000321,
    bits: 0x1d00ffff,
    nonce: 42,
  });
  const child = txRaw(
    [{ txid: new Uint8Array(32), index: 0xffffffff }],
    [{ amount: 6000n, script }]
  );
  const electrum = await fakeElectrum((req) => {
    const [a, b] = req.params;
    if (req.method === 'blockchain.headers.subscribe') return { height: 321 };
    if (req.method === 'blockchain.block.header' && a === 321) return header.hex;
    if (req.method === 'blockchain.block.header' && typeof a === 'number')
      return blockHeader({
        version: 0x20000000,
        parent: '11'.repeat(32),
        merkleRoot: '22'.repeat(32),
        timestamp: 1710000321,
        bits: 0x1d00ffff,
        nonce: a,
      }).hex;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 321 && b === 0)
      return child.txid;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 321 && b === 1)
      return Promise.reject(new Error('socket reset'));
    if (req.method === 'blockchain.transaction.get' && a === child.txid) return child.hex;
    return Promise.reject(new Error(`unexpected method ${req.method}`));
  });
  const proxy = await startProxy({
    electrum: electrum.url,
    listen: '127.0.0.1:0',
    network: regtest,
  });
  try {
    const res = await fetch(`${proxy.url}/block/${header.hash}`);
    deepStrictEqual(
      { status: res.status, body: await res.json() },
      { status: 500, body: { error: 'socket reset' } }
    );
  } finally {
    await proxy.close();
    await electrum.close();
  }
});

it('test/proxy: accepts romanz block txid end marker', async () => {
  const header = blockHeader({
    version: 0x20000000,
    parent: '11'.repeat(32),
    merkleRoot: '22'.repeat(32),
    timestamp: 1710000321,
    bits: 0x1d00ffff,
    nonce: 42,
  });
  const child = txRaw(
    [{ txid: new Uint8Array(32), index: 0xffffffff }],
    [{ amount: 6000n, script }]
  );
  const electrum = await fakeElectrum((req) => {
    const [a, b] = req.params;
    if (req.method === 'blockchain.block.header' && a === 321) return header.hex;
    if (req.method === 'blockchain.block.header' && typeof a === 'number')
      return blockHeader({
        version: 0x20000000,
        parent: '11'.repeat(32),
        merkleRoot: '22'.repeat(32),
        timestamp: 1710000321,
        bits: 0x1d00ffff,
        nonce: a,
      }).hex;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 321 && b === 0)
      return child.txid;
    if (req.method === 'blockchain.transaction.id_from_pos' && a === 321 && b === 1)
      return Promise.reject(new Error('invalid tx_pos 1 in block at height 321'));
    if (req.method === 'blockchain.transaction.get' && a === child.txid) return child.hex;
    return Promise.reject(new Error(`unexpected method ${req.method}`));
  });
  const proxy = await startProxy({
    electrum: electrum.url,
    listen: '127.0.0.1:0',
    network: regtest,
  });
  try {
    const provider = new EsploraProvider(fetch, proxy.url, regtest);
    deepStrictEqual(await provider.blockInfo(321), {
      hash: header.hash,
      number: 321,
      version: 0x20000000,
      timestamp: 1710000321000,
      size: 80 + 1 + child.raw.length,
      weight: 324 + child.raw.length * 4,
      merkleRoot: '22'.repeat(32),
      parentHash: '11'.repeat(32),
      medianTime: 1710000321000,
      nonce: 42,
      bits: 0x1d00ffff,
      difficulty: 1,
      transactions: [child.txid],
    });
  } finally {
    await proxy.close();
    await electrum.close();
  }
});

it('test/proxy: computes address funded and spent sums', async () => {
  const funding = txRaw(
    [{ txid: new Uint8Array(32), index: 0xffffffff }],
    [{ amount: 6000n, script }]
  );
  const child = txRaw(
    [{ txid: hex.decode(funding.txid), index: 0 }],
    [
      { amount: 4000n, script: otherScript },
      { amount: 1860n, script: new Uint8Array([0x6a]) },
    ]
  );
  const electrum = await fakeElectrum((req) => {
    const [a, b] = req.params;
    if (req.method === 'blockchain.scripthash.get_history')
      return [
        { tx_hash: funding.txid, height: 10 },
        { tx_hash: child.txid, height: 11 },
      ];
    if (req.method === 'blockchain.transaction.get') {
      const raw = a === child.txid ? child : funding;
      if (b)
        return { hex: raw.hex, blockhash: '33'.repeat(32), time: 1710000000, confirmations: 1 };
      return raw.hex;
    }
    if (req.method === 'blockchain.block.header' && typeof a === 'number')
      return blockHeader({
        version: 0x20000000,
        parent: '11'.repeat(32),
        merkleRoot: '22'.repeat(32),
        timestamp: 1710000000 + a,
        bits: 0x1d00ffff,
        nonce: a,
      }).hex;
    return Promise.reject(new Error(`unexpected method ${req.method}`));
  });
  const proxy = await startProxy({
    electrum: electrum.url,
    listen: '127.0.0.1:0',
    network: regtest,
  });
  try {
    const res = await fetch(`${proxy.url}/address/${addr}`);
    deepStrictEqual(await res.json(), {
      address: addr,
      chain_stats: {
        funded_txo_count: 1,
        funded_txo_sum: 6000,
        spent_txo_count: 1,
        spent_txo_sum: 6000,
        tx_count: 2,
      },
      mempool_stats: {
        funded_txo_count: 0,
        funded_txo_sum: 0,
        spent_txo_count: 0,
        spent_txo_sum: 0,
        tx_count: 0,
      },
    });
    const provider = new EsploraProvider(fetch, proxy.url, regtest);
    deepStrictEqual(await provider.balance(addr), {
      symbol: 'BTC',
      decimals: 8,
      balance: 0n,
      txCount: 2,
    });
  } finally {
    await proxy.close();
    await electrum.close();
  }
});

it('test/proxy: orders same-block address transactions like Esplora', async () => {
  const tx0 = txRaw([{ txid: new Uint8Array(32), index: 0xffffffff }], [{ amount: 6000n, script }]);
  const tx1 = txRaw([{ txid: new Uint8Array(32), index: 0xffffffff }], [{ amount: 7000n, script }]);
  const electrum = await fakeElectrum((req) => {
    const [a, b] = req.params;
    if (req.method === 'blockchain.scripthash.get_history')
      return [
        { tx_hash: tx0.txid, height: 321 },
        { tx_hash: tx1.txid, height: 321 },
      ];
    if (req.method === 'blockchain.transaction.get') {
      const raw = a === tx1.txid ? tx1 : tx0;
      if (b)
        return { hex: raw.hex, blockhash: '33'.repeat(32), time: 1710000000, confirmations: 1 };
      return raw.hex;
    }
    if (req.method === 'blockchain.block.header' && a === 321)
      return blockHeader({
        version: 0x20000000,
        parent: '11'.repeat(32),
        merkleRoot: '22'.repeat(32),
        timestamp: 1710000000,
        bits: 0x1d00ffff,
        nonce: 321,
      }).hex;
    return Promise.reject(new Error(`unexpected method ${req.method}`));
  });
  const proxy = await startProxy({
    electrum: electrum.url,
    listen: '127.0.0.1:0',
    network: regtest,
  });
  try {
    const order = [tx0.txid, tx1.txid].sort((a, b) => reverseTxid(b).localeCompare(reverseTxid(a)));
    const txs = await fetch(`${proxy.url}/address/${addr}/txs`);
    deepStrictEqual(
      (await txs.json()).map((tx: { txid: string }) => tx.txid),
      order
    );
    const provider = new EsploraProvider(fetch, proxy.url, regtest);
    deepStrictEqual(
      (await provider.transfers(addr, { limit: 1 })).map((tx) => tx.txid),
      [order[0]]
    );
  } finally {
    await proxy.close();
    await electrum.close();
  }
});

if (!LIVE_URL && !LIVE_ELECTRUM) {
  it('EsploraProvider: blockInfo smoke', async () => {
    const replay = mftch.replayable(fetch, NET_BASIC, {
      getKey,
      offline: true,
    });
    const provider = new EsploraProvider(replay, NODE_URL);
    const block = await provider.blockInfo(1);
    deepStrictEqual(
      {
        number: block.number,
        hashLength: block.hash.length,
        txids: block.transactions.length,
      },
      { number: 1, hashLength: 64, txids: 1 }
    );
  });
}

if (LIVE_URL || LIVE_ELECTRUM) {
  it('test/proxy: matches Esplora HTTP through raw Electrum', async () => {
    if (!LIVE_URL || !LIVE_ELECTRUM)
      throw new Error('expected ESPLORA_URL and SCURE_BTC_ELECTRUM_URL');
    const body = async (
      base: string,
      path: string,
      opts?: { method?: string; headers?: Record<string, string>; body?: string }
    ) => {
      const res = await fetch(`${base}${path}`, opts);
      const text = await res.text();
      let parsed: unknown = text;
      const trimmed = text.trim();
      if (
        (res.headers.get('content-type') || '').includes('application/json') ||
        trimmed.startsWith('{') ||
        trimmed.startsWith('[')
      )
        parsed = JSON.parse(text);
      return { status: res.status, body: parsed };
    };
    const compareRoute = async (
      name: string,
      path: string,
      opts?: { method?: string; headers?: Record<string, string>; body?: string }
    ) => {
      const [expected, actual] = await Promise.all([
        body(LIVE_URL, path, opts),
        body(proxy.url, path, opts),
      ]);
      deepStrictEqual(actual, expected, name);
    };
    const direct = new EsploraProvider(fetch, LIVE_URL);
    const proxy = await startProxy({ electrum: LIVE_ELECTRUM, listen: '127.0.0.1:0' });
    const proxied = new EsploraProvider(fetch, proxy.url);
    const compare = async <T>(name: string, fn: (provider: EsploraProvider) => Promise<T>) => {
      const [expected, actual] = await Promise.all([fn(direct), fn(proxied)]);
      deepStrictEqual(actual, expected, name);
    };
    try {
      const blockHash = (await body(LIVE_URL, '/block-height/1')).body;
      if (typeof blockHash !== 'string' || !/^[0-9a-f]{64}$/.test(blockHash))
        throw new Error('expected block-height/1 hash');
      const first = (await body(LIVE_URL, `/address/${TAPROOT_ADDR}/txs`)).body;
      if (!Array.isArray(first) || first.length < 2) throw new Error('expected taproot tx page');
      await compareRoute('GET /blocks/tip/height', '/blocks/tip/height');
      await compareRoute('GET /block-height/:height', '/block-height/1');
      await compareRoute('GET /block/:hash', `/block/${blockHash}`);
      await compareRoute('GET /block/:hash/txids', `/block/${blockHash}/txids`);
      await compareRoute('GET /fee-estimates', '/fee-estimates');
      await compareRoute('GET /tx/:txid', `/tx/${TAPROOT_TX}`);
      await compareRoute('GET /tx/:txid/hex', `/tx/${TAPROOT_TX}/hex`);
      await compareRoute('GET /address/:address', `/address/${TAPROOT_ADDR}`);
      await compareRoute('GET /address/:address/utxo', `/address/${UNSPENT_ADDR}/utxo`);
      await compareRoute('GET /address/:address/txs', `/address/${TAPROOT_ADDR}/txs`);
      await compareRoute(
        'GET /address/:address/txs/chain/:last',
        `/address/${TAPROOT_ADDR}/txs/chain/${(first[0] as { txid: string }).txid}`
      );
      await compareRoute('POST /tx', '/tx', {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: TAPROOT_RAW,
      });
      await compare('height', (provider) => provider.height());
      await compare('blockInfo(1)', (provider) => provider.blockInfo(1));
      await compare('fee(2)', (provider) => provider.fee(2));
      await compare('balance(taproot)', (provider) => provider.balance(TAPROOT_ADDR));
      await compare('txCount(taproot)', (provider) => provider.txCount(TAPROOT_ADDR));
      await compare('transfers(taproot)', (provider) => provider.transfers(TAPROOT_ADDR));
      for (const [name, opts] of PAGE_CASES)
        await compare(`transfers(${name})`, (provider) => provider.transfers(OLD_ADDR, opts));
      await compare('txInfo(taproot)', (provider) => provider.txInfo(TAPROOT_TX));
      await compare('unspent(p2pkh)', (provider) => provider.unspent(UNSPENT_ADDR));
    } finally {
      await proxy.close();
    }
  });
}

// Keep the proxy smoke test runnable directly without pulling it into cross-runtime package tests.
it.runWhen(import.meta.url);

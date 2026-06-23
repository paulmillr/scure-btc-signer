import { deepStrictEqual } from 'node:assert';
import { performance } from 'node:perf_hooks';
import type {
  Balance,
  EsploraProvider as Provider,
  TxInfo,
  TxTransfers,
  Unspent,
} from '../src/net.ts';
import { EsploraProvider } from '../src/net.ts';
import { startProxy } from '../test/misc/proxy.ts';

const DEFAULT_DIRECT = 'http://127.0.0.1:3000';
const DEFAULT_BLOCKSTREAM = 'tcp://127.0.0.1:51001';
const DEFAULT_ROMANZ = 'tcp://127.0.0.1:50001';
const DEFAULT_BUSY = 'bc1qkptzwdmhatx8f05jp2ughdacgut4fcafn27rfs';

type Opts = {
  direct: string;
  blockstream: string;
  romanz: string;
  runs: number;
  address?: string;
  txid?: string;
  busyAddress: string;
  busyLimit: number;
  help?: boolean;
};
type Fixture = { address: string; txid: string; count: number };
type Variant = { name: string; provider: Provider; close?: () => Promise<void> };
type Stat = { min: number; p50: number; max: number };

const usage = `usage: node benchmark/network.ts [--runs N] [--address ADDR --txid TXID]
  [--busy-address ADDR] [--busy-limit N]
  [--direct http://127.0.0.1:3000]
  [--blockstream tcp://127.0.0.1:51001]
  [--romanz tcp://127.0.0.1:50001]
`;

const parse = (args: string[]): Opts => {
  const opts: Opts = {
    direct: DEFAULT_DIRECT,
    blockstream: DEFAULT_BLOCKSTREAM,
    romanz: DEFAULT_ROMANZ,
    runs: 5,
    busyAddress: DEFAULT_BUSY,
    busyLimit: 1000,
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = () => {
      const value = args[++i];
      if (!value) throw new Error(`missing value for ${arg}`);
      return value;
    };
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--direct') opts.direct = next();
    else if (arg === '--blockstream') opts.blockstream = next();
    else if (arg === '--romanz') opts.romanz = next();
    else if (arg === '--address') opts.address = next();
    else if (arg === '--txid') opts.txid = next();
    else if (arg === '--busy-address') opts.busyAddress = next();
    else if (arg === '--busy-limit') opts.busyLimit = Number(next());
    else if (arg === '--runs') opts.runs = Number(next());
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!Number.isSafeInteger(opts.runs) || opts.runs <= 0) throw new Error('expected --runs > 0');
  if (!Number.isSafeInteger(opts.busyLimit) || opts.busyLimit <= 0)
    throw new Error('expected --busy-limit > 0');
  if (!!opts.address !== !!opts.txid) throw new Error('expected both --address and --txid');
  return opts;
};

const check = async (url: string) => {
  const res = await fetch(url);
  if (res.ok) return res;
  let body = '';
  try {
    body = await res.text();
  } catch (e) {}
  throw new Error(`GET ${url} failed ${res.status} ${res.statusText}: ${body}`);
};
const text = async (url: string): Promise<string> => (await check(url)).text();
const json = async (url: string): Promise<unknown> => (await check(url)).json();
const rec = (value: unknown, name: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`expected ${name} object`);
  return value as Record<string, unknown>;
};
const arr = (value: unknown, name: string): unknown[] => {
  if (!Array.isArray(value)) throw new Error(`expected ${name} array`);
  return value;
};
const str = (value: unknown): string | undefined => (typeof value === 'string' ? value : undefined);
const num = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isSafeInteger(value) ? value : undefined;
const count = (value: unknown): number => {
  const raw = rec(value, 'address');
  const chain = rec(raw.chain_stats, 'chain_stats');
  const mempool = rec(raw.mempool_stats, 'mempool_stats');
  const a = num(chain.tx_count);
  const b = num(mempool.tx_count);
  if (a === undefined || b === undefined) throw new Error('expected tx counts');
  return a + b;
};

const discover = async (base: string): Promise<Fixture> => {
  const tip = Number((await text(`${base}/blocks/tip/height`)).trim());
  if (!Number.isSafeInteger(tip)) throw new Error('expected direct Esplora tip height');
  for (let height = tip; height >= tip - 24; height--) {
    const hash = (await text(`${base}/block-height/${height}`)).trim();
    const txs = arr(await json(`${base}/block/${hash}/txs/0`), 'block txs');
    for (const rawTx of txs.slice(1)) {
      const tx = rec(rawTx, 'tx');
      const txid = str(tx.txid);
      if (!txid || num(tx.version) !== 2) continue;
      for (const rawOut of arr(tx.vout, 'vout')) {
        const out = rec(rawOut, 'output');
        const address = str(out.scriptpubkey_address);
        const value = num(out.value);
        if (!address || value === undefined || value <= 546) continue;
        const txCount = count(await json(`${base}/address/${address}`));
        if (txCount !== 1) continue;
        const utxos = arr(await json(`${base}/address/${address}/utxo`), 'utxo');
        if (utxos.length !== 1) continue;
        return { address, txid, count: txCount };
      }
    }
  }
  throw new Error('could not discover a small recent address fixture');
};

const txSummary = (tx: TxInfo) => ({
  txid: tx.txid,
  version: tx.version,
  lockTime: tx.lockTime,
  size: tx.size,
  weight: tx.weight,
  fee: tx.fee.toString(),
  inputs: tx.inputs.length,
  outputs: tx.outputs.length,
  raw: tx.raw,
});
const inputRawLen = (value: unknown): number => {
  if (typeof value === 'string') return value.length / 2;
  if (value instanceof Uint8Array) return value.length;
  return 0;
};
const utxoSummary = (value: Unspent) => ({
  balance: value.balance.toString(),
  utxo: value.utxo.map(
    (i) => `${String(i.txid)}:${String(i.index)}:${inputRawLen(i.nonWitnessUtxo)}`
  ),
});
const balanceSummary = (value: Balance) => ({
  balance: value.balance.toString(),
  txCount: value.txCount,
});
const transferSummary = (txs: TxTransfers[]) =>
  txs.map((tx) => ({
    txid: tx.txid,
    block: tx.block,
    fee: tx.info.fee.toString(),
    raw: tx.info.raw,
    transfers: tx.transfers.map((i) => ({
      from: i.from,
      to: i.to,
      value: i.value.toString(),
    })),
  }));
const snapshot = async (provider: Provider, fixture: Fixture) => ({
  txCount: await provider.txCount(fixture.address),
  tx: txSummary(await provider.txInfo(fixture.txid)),
  unspent: utxoSummary(await provider.unspent(fixture.address)),
  transfers: transferSummary(await provider.transfers(fixture.address, { limit: 1 })),
});
const busySnapshot = async (provider: Provider, address: string, limit: number) => ({
  balance: balanceSummary(await provider.balance(address)),
  transfers: transferSummary(await provider.transfers(address, { limit })),
});
const validate = async (variants: Variant[], fixture: Fixture) => {
  const baseline = await snapshot(variants[0].provider, fixture);
  deepStrictEqual(baseline.txCount, fixture.count);
  for (const variant of variants.slice(1)) {
    const cur = await snapshot(variant.provider, fixture);
    deepStrictEqual(cur, baseline, `${variant.name} differs from ${variants[0].name}`);
  }
  for (const variant of variants) {
    const height = await variant.provider.height();
    const fee = await variant.provider.fee(2);
    if (!Number.isSafeInteger(height) || height <= 0)
      throw new Error(`${variant.name}: bad height`);
    if (fee <= 0n) throw new Error(`${variant.name}: bad fee`);
  }
};
const validateBusy = async (variants: Variant[], address: string, limit: number) => {
  const baseline = await busySnapshot(variants[0].provider, address, limit);
  if (baseline.balance.txCount < limit)
    throw new Error(`busy address has ${baseline.balance.txCount} txs, below limit=${limit}`);
  for (const variant of variants.slice(1)) {
    const cur = await busySnapshot(variant.provider, address, limit);
    deepStrictEqual(cur, baseline, `${variant.name} busy address differs from ${variants[0].name}`);
  }
};

const stats = (values: number[]): Stat => {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    min: sorted[0],
    p50: sorted[Math.floor(sorted.length / 2)],
    max: sorted[sorted.length - 1],
  };
};
const measure = async (runs: number, fn: () => Promise<unknown>): Promise<Stat> => {
  const values = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    await fn();
    values.push(performance.now() - start);
  }
  return stats(values);
};
const fmt = (value: number): string => value.toFixed(1).padStart(8);
const opWidth = (ops: { name: string }[]) =>
  Math.max('op'.length, ...ops.map((op) => op.name.length));

const main = async () => {
  const opts = parse(process.argv.slice(2));
  if (opts.help) {
    console.log(usage);
    return;
  }
  const fixture =
    opts.address && opts.txid
      ? { address: opts.address, txid: opts.txid, count: 1 }
      : await discover(opts.direct);
  const blockstream = await startProxy({ electrum: opts.blockstream, listen: '127.0.0.1:0' });
  const romanz = await startProxy({ electrum: opts.romanz, listen: '127.0.0.1:0' });
  const variants: Variant[] = [
    { name: 'direct-esplora', provider: new EsploraProvider(fetch, opts.direct) },
    {
      name: 'blockstream-proxy',
      provider: new EsploraProvider(fetch, blockstream.url),
      close: blockstream.close,
    },
    { name: 'romanz-proxy', provider: new EsploraProvider(fetch, romanz.url), close: romanz.close },
  ];
  try {
    await validate(variants, fixture);
    await validateBusy(variants, opts.busyAddress, opts.busyLimit);
    console.log(`fixture address=${fixture.address} txid=${fixture.txid}`);
    console.log(`busy address=${opts.busyAddress} limit=${opts.busyLimit}`);
    console.log(`runs=${opts.runs}; timings are milliseconds, correctness validated first`);
    const ops = [
      { name: 'height', run: (p: Provider) => p.height() },
      { name: 'fee', run: (p: Provider) => p.fee(2) },
      { name: 'txCount', run: (p: Provider) => p.txCount(fixture.address) },
      { name: 'txInfo', run: (p: Provider) => p.txInfo(fixture.txid) },
      { name: 'unspent', run: (p: Provider) => p.unspent(fixture.address) },
      { name: 'transfers', run: (p: Provider) => p.transfers(fixture.address, { limit: 1 }) },
      { name: 'busyBalance', run: (p: Provider) => p.balance(opts.busyAddress) },
      {
        name: `busyTransfers${opts.busyLimit}`,
        run: (p: Provider) => p.transfers(opts.busyAddress, { limit: opts.busyLimit }),
      },
    ];
    const width = opWidth(ops);
    console.log(
      `${'variant'.padEnd(18)} ${'op'.padEnd(width)} ${'min'.padStart(8)} ${'p50'.padStart(8)} ${'max'.padStart(8)}`
    );
    for (const variant of variants) {
      for (const op of ops) {
        const s = await measure(opts.runs, () => op.run(variant.provider));
        console.log(
          `${variant.name.padEnd(18)} ${op.name.padEnd(width)} ${fmt(s.min)} ${fmt(s.p50)} ${fmt(s.max)}`
        );
      }
    }
  } finally {
    for (const variant of variants) await variant.close?.();
  }
};

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});

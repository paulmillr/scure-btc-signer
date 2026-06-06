import { hex } from '@scure/base';
import { Address } from './payment.ts';
import type * as psbt from './psbt.ts';
import {
  getPrevOut,
  inputBeforeSign,
  normalizeInput,
  PRECISION,
  Transaction,
} from './transaction.ts';
import { NETWORK, type BTC_NETWORK, type TArg, type TRet } from './utils.ts';

// Be friendly to bad ECMAScript parsers by not using bigint literals.
const _0n = /* @__PURE__ */ BigInt(0);

/** Subclass for all EsploraProvider related errors */
export class EsploraError extends Error {}

type FetchOpts = { method?: string; headers?: Record<string, string>; body?: string };
type FetchResponse = {
  ok: boolean;
  status: number;
  statusText?: string;
  json(): Promise<unknown>;
  text(): Promise<string>;
};
/** Minimal fetch-compatible transport accepted by {@link EsploraProvider}. */
export type FetchFn = (url: string, opts?: FetchOpts) => Promise<FetchResponse>;
/** Confirmation metadata from Esplora-compatible transaction responses. */
export type TxStatus = {
  /** Whether the transaction is confirmed in a block. */
  confirmed: boolean;
  /** Confirming block height, absent for mempool transactions. */
  block?: number;
  /** Confirming block hash, absent for mempool transactions. */
  blockHash?: string;
  /** Confirming block timestamp in milliseconds, absent for mempool transactions. */
  timestamp?: number;
};
/** Transaction output as reported by Esplora-compatible APIs. */
export type TxOutput = {
  /** Hex-encoded scriptPubKey. */
  scriptPubKey: string;
  /** Decoded address when the script has a known address form. */
  scriptPubKeyAddress?: string;
  /** Output value in satoshis. */
  value: bigint;
};
/** Transaction input as reported by Esplora-compatible APIs. */
export type TxInput = {
  /** Previous transaction id for non-coinbase inputs. */
  txid?: string;
  /** Previous output index for non-coinbase inputs. */
  index?: number;
  /** Previous output details when supplied by the backend. */
  prevout?: TxOutput;
  /** Input sequence number. */
  sequence?: number;
  /** Whether this input is a coinbase input. */
  isCoinbase?: boolean;
};
/** Full Bitcoin transaction metadata returned by {@link EsploraProvider.txInfo}. */
export type TxInfo = {
  /** Transaction id. */
  txid: string;
  /** Transaction version. */
  version: number;
  /** Transaction locktime. */
  lockTime: number;
  /** Serialized transaction size in bytes. */
  size: number;
  /** Transaction weight units. */
  weight: number;
  /** Fee paid by the transaction in satoshis. */
  fee: bigint;
  /** Transaction inputs. */
  inputs: TxInput[];
  /** Transaction outputs. */
  outputs: TxOutput[];
  /** Confirmation status. */
  status: TxStatus;
  /** Hex-encoded raw transaction. */
  raw: string;
};
/** Block metadata returned by Esplora-compatible APIs. */
export type BlockInfo = {
  /** Block hash. */
  hash: string;
  /** Block number / height. */
  number: number;
  /** Block version. */
  version: number;
  /** Block timestamp in milliseconds. */
  timestamp: number;
  /** Serialized block size in bytes. */
  size: number;
  /** Block weight units. */
  weight: number;
  /** Merkle root hash. */
  merkleRoot: string;
  /** Previous block hash, absent for genesis. */
  parentHash?: string;
  /** Median block timestamp in milliseconds when the backend returns it. */
  medianTime?: number;
  /** Block nonce. */
  nonce?: number;
  /** Compact difficulty bits. */
  bits?: number;
  /** Floating-point network difficulty. */
  difficulty?: number;
  /** Transaction hashes in block order. */
  transactions: string[];
};
/** Value movement entry derived from Bitcoin transaction inputs or outputs. */
export type Transfer = {
  /** Source address for input-side movements, absent when the backend cannot decode one. */
  from?: string;
  /** Destination address for output-side movements, absent for scripts without address form. */
  to?: string;
  /** Value in satoshis. */
  value: bigint;
};
/** Address-history transaction with transfer records and compact transaction metadata. */
export type TxTransfers = {
  /** Transaction id. */
  txid: string;
  /** Confirming block timestamp in milliseconds, absent for mempool transactions. */
  timestamp?: number;
  /** Confirming block height, absent for mempool transactions. */
  block?: number;
  /** Input and output value movements for the whole transaction. */
  transfers: Transfer[];
  /** Compact transaction metadata useful for wallet history. */
  info: {
    /** Transaction version. */
    version: number;
    /** Transaction locktime. */
    lockTime: number;
    /** Serialized transaction size in bytes. */
    size: number;
    /** Transaction weight units. */
    weight: number;
    /** Transaction fee in satoshis. */
    fee: bigint;
    /** Confirming block hash, absent for mempool transactions. */
    blockHash?: string;
    /** Hex-encoded raw transaction. */
    raw: string;
  };
};
/** UTXO set for an address in a shape accepted by transaction builders. */
export type Unspent = {
  /** Asset symbol. */
  symbol: 'BTC';
  /** Decimal precision for BTC amounts. */
  decimals: number;
  /** Sum of returned spendable outputs in satoshis. */
  balance: bigint;
  /** Input updates that can be passed to `Transaction.addInput` or `selectUTXO`. */
  utxo: psbt.TransactionInputUpdate[];
};
/** Lightweight address balance from Esplora stats, without enumerating UTXOs. */
export type Balance = {
  /** Asset symbol. */
  symbol: 'BTC';
  /** Decimal precision for BTC amounts. */
  decimals: number;
  /** Current address balance in satoshis. */
  balance: bigint;
  /** Confirmed plus mempool transaction count. */
  txCount: number;
};
/** Address-history pagination and filtering options. */
export type TransfersOpts = {
  /** Inclusive lower block bound. */
  fromBlock?: number;
  /** Inclusive upper block bound. */
  toBlock?: number;
  /** Maximum number of matching transactions to return. */
  limit?: number;
  /** Return transactions older than this address-history cursor txid. */
  afterTxid?: string;
};
/** Running balance snapshot attached by {@link calcTransfersDiff}. */
export type Balances = {
  /** Running satoshi balance by address after this transaction. */
  balances: Record<string, bigint>;
};

const HEX64 = /^[0-9a-fA-F]{64}$/;
const ESPLORA_PER_PAGE = 25;
const validateRecord = (value: unknown, name: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new EsploraError(`expected ${name} object`);
  return value as Record<string, unknown>;
};
const validateArray = (value: unknown, name: string): unknown[] => {
  if (!Array.isArray(value)) throw new EsploraError(`expected ${name} array`);
  return value;
};
const validateString = (value: unknown, name: string): string => {
  if (typeof value !== 'string') throw new EsploraError(`expected ${name} string`);
  return value;
};
const validateBool = (value: unknown, name: string): boolean => {
  if (typeof value !== 'boolean') throw new EsploraError(`expected ${name} boolean`);
  return value;
};
const validateInt = (value: unknown, name: string): number => {
  const num = typeof value === 'string' && /^-?[0-9]+$/.test(value) ? Number(value) : value;
  if (typeof num !== 'number' || !Number.isSafeInteger(num))
    throw new EsploraError(`expected ${name} safe integer`);
  return num;
};
const validateUint = (value: unknown, name: string): number => {
  const num = validateInt(value, name);
  if (num < 0) throw new EsploraError(`expected ${name} non-negative safe integer`);
  return num;
};
const validatePositiveInt = (value: unknown, name: string): number => {
  const num = validateInt(value, name);
  if (num <= 0) throw new EsploraError(`expected ${name} positive safe integer`);
  return num;
};
const validateBigint = (value: unknown, name: string): bigint => {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && /^[0-9]+$/.test(value)) return BigInt(value);
  throw new EsploraError(`expected ${name} non-negative integer`);
};
const pickString = (obj: Record<string, unknown>, key: string, name: string): string =>
  validateString(obj[key], name);
const validateHash = (value: string, name: string): string => {
  if (!HEX64.test(value)) throw new EsploraError(`expected ${name} hex string`);
  return value.toLowerCase();
};
const txidPath = (txid: string): string => {
  if (typeof txid !== 'string') throw new EsploraError('expected txid hex string');
  return validateHash(txid, 'txid');
};
const parseRawTx = (raw: string, txid: string): void => {
  const tx = Transaction.fromRaw(hex.decode(raw), {
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
    disableScriptCheck: true,
  });
  if (tx.id !== txid)
    throw new EsploraError(`wrong raw txid, expected ${txid} got ${tx.id}`);
};
const validateTransfersOpts = (opts: TArg<TransfersOpts>): TRet<TransfersOpts> => {
  if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
    throw new EsploraError('expected transfer options object');
  const res = { ...opts } as TransfersOpts;
  if (res.fromBlock !== undefined) res.fromBlock = validateUint(res.fromBlock, 'fromBlock');
  if (res.toBlock !== undefined) res.toBlock = validateUint(res.toBlock, 'toBlock');
  if (res.limit !== undefined) res.limit = validatePositiveInt(res.limit, 'limit');
  if (res.afterTxid !== undefined) res.afterTxid = validateHash(res.afterTxid, 'afterTxid');
  if (res.fromBlock !== undefined && res.toBlock !== undefined && res.toBlock < res.fromBlock)
    throw new EsploraError('expected toBlock >= fromBlock');
  if (res.afterTxid !== undefined && (res.fromBlock !== undefined || res.toBlock !== undefined))
    throw new EsploraError('expected afterTxid without block range');
  return res as TRet<TransfersOpts>;
};
const fixStatus = (value: unknown): TxStatus => {
  const raw = validateRecord(value, 'tx.status');
  // Esplora uses snake_case and second timestamps; expose the same compact names and
  // millisecond timestamps as the rest of this provider surface.
  const res: TxStatus = { confirmed: validateBool(raw.confirmed, 'status.confirmed') };
  if (raw.block_height !== undefined) res.block = validateUint(raw.block_height, 'block_height');
  if (raw.block_hash !== undefined)
    res.blockHash = validateHash(validateString(raw.block_hash, 'block_hash'), 'block_hash');
  if (raw.block_time !== undefined)
    res.timestamp = validateUint(raw.block_time, 'block_time') * 1000;
  return res;
};
const fixOutput = (value: unknown): TxOutput => {
  const raw = validateRecord(value, 'tx.output');
  const res: TxOutput = {
    scriptPubKey: pickString(raw, 'scriptpubkey', 'scriptpubkey'),
    value: validateBigint(raw.value, 'output.value'),
  };
  if (raw.scriptpubkey_address !== undefined)
    res.scriptPubKeyAddress = validateString(raw.scriptpubkey_address, 'scriptpubkey_address');
  return res;
};
const fixInput = (value: unknown): TxInput => {
  const raw = validateRecord(value, 'tx.input');
  const res: TxInput = {};
  if (raw.txid !== undefined)
    res.txid = validateHash(validateString(raw.txid, 'input.txid'), 'input.txid');
  if (raw.vout !== undefined) res.index = validateUint(raw.vout, 'input.vout');
  if (raw.prevout !== undefined && raw.prevout) res.prevout = fixOutput(raw.prevout);
  if (raw.sequence !== undefined) res.sequence = validateUint(raw.sequence, 'input.sequence');
  if (raw.is_coinbase !== undefined)
    res.isCoinbase = validateBool(raw.is_coinbase, 'input.is_coinbase');
  return res;
};
const fixTx = (value: unknown): Omit<TxInfo, 'raw'> => {
  const raw = validateRecord(value, 'tx');
  return {
    txid: validateHash(pickString(raw, 'txid', 'txid'), 'txid'),
    version: validateInt(raw.version, 'version'),
    lockTime: validateUint(raw.locktime, 'locktime'),
    size: validateUint(raw.size, 'size'),
    weight: validateUint(raw.weight, 'weight'),
    fee: validateBigint(raw.fee, 'fee'),
    inputs: validateArray(raw.vin, 'vin').map(fixInput),
    outputs: validateArray(raw.vout, 'vout').map(fixOutput),
    status: fixStatus(raw.status),
  };
};
const fixBlock = (value: unknown, transactions: string[]): BlockInfo => {
  const raw = validateRecord(value, 'block');
  const res: BlockInfo = {
    hash: validateHash(pickString(raw, 'id', 'block.id'), 'block.id'),
    number: validateUint(raw.height, 'block.height'),
    version: validateInt(raw.version, 'block.version'),
    timestamp: validateUint(raw.timestamp, 'block.timestamp') * 1000,
    size: validateUint(raw.size, 'block.size'),
    weight: validateUint(raw.weight, 'block.weight'),
    merkleRoot: validateHash(pickString(raw, 'merkle_root', 'block.merkle_root'), 'merkle_root'),
    transactions,
  };
  if (raw.previousblockhash !== undefined)
    res.parentHash = validateHash(
      validateString(raw.previousblockhash, 'previousblockhash'),
      'previousblockhash'
    );
  if (raw.mediantime !== undefined)
    res.medianTime = validateUint(raw.mediantime, 'block.mediantime') * 1000;
  if (raw.nonce !== undefined) res.nonce = validateUint(raw.nonce, 'block.nonce');
  if (raw.bits !== undefined) res.bits = validateUint(raw.bits, 'block.bits');
  if (raw.difficulty !== undefined) {
    const difficulty =
      typeof raw.difficulty === 'string' && /^[0-9]+(?:\.[0-9]+)?$/.test(raw.difficulty)
        ? Number(raw.difficulty)
        : raw.difficulty;
    if (typeof difficulty !== 'number' || !Number.isFinite(difficulty))
      throw new EsploraError('expected block.difficulty finite number');
    res.difficulty = difficulty;
  }
  return res;
};

/**
 * Esplora-compatible Bitcoin HTTP provider.
 *
 * Runtime transport is caller-provided `fetch`. The repository `test/proxy.ts`
 * bridge is test/dev tooling for serving the wallet/history HTTP subset from Electrum TCP.
 * @param fetch - Fetch-compatible HTTP transport.
 * @param url - Base URL of an Esplora-compatible HTTP API.
 * @param network - Bitcoin address network parameters.
 * @example
 * Create a provider with a caller-owned transport.
 * ```ts
 * import { EsploraProvider } from '@scure/btc-signer/net.js';
 * const httpFetch = async () => ({
 *   ok: true,
 *   status: 200,
 *   text: async () => '1',
 *   json: async () => ({ '2': 1 }),
 * });
 * const net = new EsploraProvider(httpFetch, 'http://127.0.0.1:3000');
 * await net.height();
 * ```
 */
export class EsploraProvider {
  private fetch: FetchFn;
  private url: string;
  private address: ReturnType<typeof Address>;
  constructor(fetch: FetchFn, url: string, network: BTC_NETWORK = NETWORK) {
    if (typeof fetch !== 'function') throw new EsploraError('expected fetch function');
    if (typeof url !== 'string' || !url.length) throw new EsploraError('expected url');
    this.fetch = fetch;
    this.url = url;
    this.address = Address(network);
  }
  private async request(path: string, opts: FetchOpts = {}): Promise<FetchResponse> {
    const method = opts.method || 'GET';
    const res = await this.fetch(`${this.url}${path}`, opts);
    if (res.ok) return res;
    const text = await res.text();
    const status = res.statusText ? `${res.status} ${res.statusText}` : `${res.status}`;
    const suffix = text ? `: ${text}` : '';
    throw new EsploraError(`${method} ${path} failed ${status}${suffix}`);
  }
  private addressPath(address: string): string {
    if (typeof address !== 'string') throw new EsploraError('expected address string');
    this.address.decode(address);
    return address;
  }
  private async txHex(txid: string): Promise<string> {
    return (await this.request(`/tx/${txidPath(txid)}/hex`)).text();
  }

  async height(): Promise<number> {
    return validateUint(await (await this.request('/blocks/tip/height')).text(), 'height');
  }
  async blockInfo(block: number): Promise<BlockInfo> {
    const hash = validateHash(
      await (await this.request(`/block-height/${validateUint(block, 'block')}`)).text(),
      'block hash'
    );
    const [infoRes, txidsRes] = await Promise.all([
      this.request(`/block/${hash}`),
      this.request(`/block/${hash}/txids`),
    ]);
    const [info, rawTxids] = await Promise.all([infoRes.json(), txidsRes.json()]);
    const transactions = validateArray(rawTxids, 'block.txids').map((txid) =>
      validateHash(validateString(txid, 'block.txid'), 'block.txid')
    );
    return fixBlock(info, transactions);
  }
  async fee(target = 2): Promise<bigint> {
    target = validatePositiveInt(target, 'fee target');
    const fees = validateRecord(
      await (await this.request('/fee-estimates')).json(),
      'fee-estimates'
    );
    let fee = fees[String(target)];
    if (fee === undefined) {
      const keys = Object.keys(fees)
        .map((i) => Number(i))
        .filter((i) => Number.isSafeInteger(i) && i > 0)
        .sort((a, b) => a - b);
      // Missing exact targets use the next faster estimate first; underpaying is worse than
      // overpaying by the small gap between adjacent Esplora fee targets.
      const faster = keys.filter((i) => i <= target).pop();
      const slower = keys.find((i) => i > target);
      const key = faster || slower;
      if (key !== undefined) fee = fees[String(key)];
    }
    if (typeof fee !== 'number' || !Number.isFinite(fee) || fee <= 0)
      throw new EsploraError('missing fee estimate');
    return BigInt(Math.ceil(fee));
  }
  /** Lightweight method to receive the "unspent" amount without getting the full UTXO list. */
  async balance(address: string): Promise<Balance> {
    const res = validateRecord(
      await (await this.request(`/address/${this.addressPath(address)}`)).json(),
      'address'
    );
    const chain = validateRecord(res.chain_stats, 'chain_stats');
    const mempool = validateRecord(res.mempool_stats, 'mempool_stats');
    const funded =
      validateBigint(chain.funded_txo_sum, 'chain.funded_txo_sum') +
      validateBigint(mempool.funded_txo_sum, 'mempool.funded_txo_sum');
    const spent =
      validateBigint(chain.spent_txo_sum, 'chain.spent_txo_sum') +
      validateBigint(mempool.spent_txo_sum, 'mempool.spent_txo_sum');
    const txCount =
      validateUint(chain.tx_count, 'chain.tx_count') +
      validateUint(mempool.tx_count, 'mempool.tx_count');
    return { symbol: 'BTC', decimals: PRECISION, balance: funded - spent, txCount };
  }
  async txCount(address: string): Promise<number> {
    return (await this.balance(address)).txCount;
  }
  async sendTx(tx: string): Promise<string> {
    if (typeof tx !== 'string') throw new EsploraError('expected tx hex string');
    return validateHash(
      await (
        await this.request('/tx', {
          method: 'POST',
          headers: { 'content-type': 'text/plain' },
          body: tx,
        })
      ).text(),
      'broadcast txid'
    );
  }
  async txInfo(txid: string): Promise<TxInfo> {
    const id = txidPath(txid);
    const [infoRes, raw] = await Promise.all([this.request(`/tx/${id}`), this.txHex(id)]);
    const info = fixTx(await infoRes.json());
    if (info.txid !== id)
      throw new EsploraError(`wrong txid, expected ${id} got ${info.txid}`);
    parseRawTx(raw, id);
    return { ...info, raw };
  }
  async unspent(address: string): Promise<Unspent> {
    const items = validateArray(
      await (await this.request(`/address/${this.addressPath(address)}/utxo`)).json(),
      'address.utxo'
    );
    const utxo = await Promise.all(
      items.map(async (value) => {
        const raw = validateRecord(value, 'utxo');
        const txid = validateHash(pickString(raw, 'txid', 'utxo.txid'), 'utxo.txid');
        return {
          txid,
          index: validateUint(raw.vout, 'utxo.vout'),
          nonWitnessUtxo: hex.decode(await this.txHex(txid)),
        };
      })
    );
    let balance = _0n;
    for (const input of utxo) {
      const normalized = normalizeInput(input, undefined, undefined, true);
      inputBeforeSign(normalized);
      balance += getPrevOut(normalized).amount;
    }
    return { symbol: 'BTC', decimals: PRECISION, balance, utxo };
  }
  async transfers(address: string, opts: TransfersOpts = {}): Promise<TxTransfers[]> {
    const options = validateTransfersOpts(opts);
    const addr = this.addressPath(address);
    const txs: Omit<TxInfo, 'raw'>[] = [];
    let path =
      options.afterTxid === undefined
        ? `/address/${addr}/txs`
        : `/address/${addr}/txs/chain/${options.afterTxid}`;
    let start = 0;
    if (options.afterTxid !== undefined) {
      const first = validateArray(
        await (await this.request(`/address/${addr}/txs`)).json(),
        'address.txs'
      ).map(fixTx);
      const idx = first.findIndex((tx) => tx.txid.toLowerCase() === options.afterTxid);
      if (idx !== -1) {
        path = '';
        start = idx + 1;
        for (let i = start; i < first.length; i++) {
          txs.push(first[i]);
          if (options.limit !== undefined && txs.length >= options.limit) break;
        }
        const last = first[first.length - 1];
        if (
          (options.limit === undefined || txs.length < options.limit) &&
          first.length >= ESPLORA_PER_PAGE &&
          last.status.confirmed
        ) {
          path = `/address/${addr}/txs/chain/${last.txid}`;
          start = 0;
        }
      }
    }
    while (true) {
      if (!path) break;
      const page = validateArray(await (await this.request(path)).json(), 'address.txs').map(fixTx);
      if (!page.length) break;
      for (let i = start; i < page.length; i++) {
        const tx = page[i];
        const block = tx.status.block;
        // Unconfirmed transactions have no block. Keep them in open-ended syncs, but not in fixed
        // historical ranges where callers asked for an exact block interval.
        const inRange =
          block === undefined
            ? options.toBlock === undefined
            : !(
                (options.fromBlock !== undefined && block < options.fromBlock) ||
                (options.toBlock !== undefined && block > options.toBlock)
              );
        if (inRange) txs.push(tx);
        if (options.limit !== undefined && txs.length >= options.limit) break;
      }
      if (options.limit !== undefined && txs.length >= options.limit) break;
      const last = page[page.length - 1];
      if (page.length < ESPLORA_PER_PAGE || !last.status.confirmed) break;
      if (
        options.fromBlock !== undefined &&
        last.status.block !== undefined &&
        last.status.block < options.fromBlock
      )
        break;
      path = `/address/${addr}/txs/chain/${last.txid}`;
      start = 0;
    }
    // Esplora address history is newest-first. Reverse the fetched stream instead of sorting by
    // txid; same-block txids have no chronological meaning and sorting them reshuffles page
    // boundaries when callers increase `limit` for address pagination.
    txs.reverse();
    const raws = await Promise.all(txs.map((tx) => this.txHex(tx.txid)));
    return txs.map((tx, i) => {
      parseRawTx(raws[i], tx.txid);
      const transfers: Transfer[] = [];
      for (const input of tx.inputs) {
        if (!input.prevout) continue;
        const transfer: Transfer = { value: input.prevout.value };
        if (input.prevout.scriptPubKeyAddress !== undefined)
          transfer.from = input.prevout.scriptPubKeyAddress;
        transfers.push(transfer);
      }
      for (const output of tx.outputs) {
        const transfer: Transfer = { value: output.value };
        if (output.scriptPubKeyAddress !== undefined) transfer.to = output.scriptPubKeyAddress;
        transfers.push(transfer);
      }
      const info: TxTransfers['info'] = {
        version: tx.version,
        lockTime: tx.lockTime,
        size: tx.size,
        weight: tx.weight,
        fee: tx.fee,
        raw: raws[i],
      };
      if (tx.status.blockHash !== undefined) info.blockHash = tx.status.blockHash;
      const res: TxTransfers = { txid: tx.txid, transfers, info };
      if (tx.status.timestamp !== undefined) res.timestamp = tx.status.timestamp;
      if (tx.status.block !== undefined) res.block = tx.status.block;
      return res;
    });
  }
}

/**
 * Calculates balances at specific point in time after tx.
 * Info from multiple addresses can be merged when transactions are already sorted.
 * @param transfers - Transaction transfer records.
 * @returns Same transfer records with running balance snapshots attached.
 * @example
 * Fold an address history into running balances.
 * ```ts
 * import { calcTransfersDiff } from '@scure/btc-signer/net.js';
 * calcTransfersDiff([]);
 * ```
 */
export function calcTransfersDiff(transfers: TxTransfers[]): (TxTransfers & Balances)[] {
  const balances: Record<string, bigint> = {};
  for (const tx of transfers) {
    for (const transfer of tx.transfers) {
      if (transfer.from) {
        if (balances[transfer.from] === undefined) balances[transfer.from] = _0n;
        balances[transfer.from] -= transfer.value;
      }
      if (transfer.to) {
        if (balances[transfer.to] === undefined) balances[transfer.to] = _0n;
        balances[transfer.to] += transfer.value;
      }
    }
    Object.assign(tx, { balances: { ...balances } });
  }
  return transfers as (TxTransfers & Balances)[];
}

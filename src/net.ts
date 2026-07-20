import { hex } from '@scure/base';
import { utils as packedUtils } from 'micro-packed';
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
export class EsploraError extends Error {
  // `declare`: type-only fields. Runtime properties are assigned only when
  // known, so `new EsploraError(msg)` instances used as assertion expectations
  // do not carry `status: undefined` own properties.
  declare readonly status?: number;
  declare readonly path?: string;
  constructor(message: string, opts: { status?: number; path?: string } = {}) {
    super(message);
    if (opts.status !== undefined) (this as { status?: number }).status = opts.status;
    if (opts.path !== undefined) (this as { path?: string }).path = opts.path;
  }
}

type FetchOpts = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
};
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
/** Merged multi-address history row from {@link EsploraProvider.historyMulti}. */
export type MultiTxTransfers = TxTransfers & {
  /** Watched addresses participating in this transaction's transfers. */
  addresses: string[];
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
/** Scan progress reported by {@link EsploraProvider.history} while metadata pages arrive. */
export type ScanProgress = {
  /** Transactions scanned so far, before block-range and limit filters. */
  scannedTxs: number;
  /** Confirmed plus mempool transaction count for the address, from address stats. */
  totalTxs: number;
  /** Share of the address history scanned so far, 0-100. */
  percent: number;
  /** Height of the most recently scanned confirmed transaction, absent for mempool rows. */
  currentBlock?: number;
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
  /** Aborts the scan; checked between requests and passed to the transport. */
  signal?: AbortSignal;
  /** Progress listener; costs one extra address-stats request to size the scan. */
  onProgress?: (progress: ScanProgress) => void;
  /** Maximum concurrent raw-transaction fetches (default 8). */
  concurrency?: number;
};
/** {@link EsploraProvider.history} options: transfers filters plus yield direction. */
export type HistoryOpts = TransfersOpts & {
  /**
   * Yield direction. `newest` (default) streams rows while pages arrive, so
   * stopping early also stops fetching. `oldest` (the transfers() order) must
   * buffer transaction metadata first, since Esplora only pages newest-first.
   */
  order?: 'newest' | 'oldest';
};
/** {@link EsploraProvider.unspent} scan options. */
export type UnspentOpts = {
  /** Aborts the scan; checked between requests and passed to the transport. */
  signal?: AbortSignal;
  /** Maximum concurrent raw-transaction fetches (default 8). */
  concurrency?: number;
};
/** {@link EsploraProvider.waitForTx} options. */
export type WaitTxOpts = {
  /** Blocks on top of the inclusion block, default 1 (just included). */
  confirmations?: number;
  /** Delay between status polls in milliseconds, default 5000. */
  pollIntervalMs?: number;
  /** Give up (reject) after this long; default is to wait forever. */
  timeoutMs?: number;
  /** Aborts the wait; checked between polls and passed to the transport. */
  signal?: AbortSignal;
};
/** Running balance snapshot attached by {@link calcTransfersDiff}. */
export type Balances = {
  /** Running satoshi balance by address after this transaction. */
  balances: Record<string, bigint>;
};

const HEX64 = /^[0-9a-fA-F]{64}$/;
const ESPLORA_PER_PAGE = 25;
const DEFAULT_CONCURRENCY = 8;
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
    // Consensus does not restrict nVersion; served history may contain
    // transactions with non-standard versions and must still verify.
    allowUnknownVersion: true,
  });
  if (tx.id !== txid) throw new EsploraError(`wrong raw txid, expected ${txid} got ${tx.id}`);
};
const validateOpts = <T extends object>(opts: TArg<T>): TRet<T> => {
  if (opts !== undefined && !packedUtils.isPlainObject(opts))
    throw new EsploraError(`"opts" expected object or undefined, got type=${typeof opts}`);
  return { ...opts } as TRet<T>;
};
const validateScanOpts = <T extends { concurrency?: number }>(opts: TArg<T>): TRet<T> => {
  const res = validateOpts<T>(opts);
  if (res.concurrency !== undefined)
    res.concurrency = validatePositiveInt(res.concurrency, 'concurrency');
  return res;
};
const validateTransfersOpts = (opts: TArg<TransfersOpts>): TRet<TransfersOpts> => {
  const res = validateScanOpts<TransfersOpts>(opts);
  if (res.fromBlock !== undefined) res.fromBlock = validateUint(res.fromBlock, 'fromBlock');
  if (res.toBlock !== undefined) res.toBlock = validateUint(res.toBlock, 'toBlock');
  if (res.limit !== undefined) res.limit = validatePositiveInt(res.limit, 'limit');
  if (res.afterTxid !== undefined) res.afterTxid = validateHash(res.afterTxid, 'afterTxid');
  if (res.fromBlock !== undefined && res.toBlock !== undefined && res.toBlock < res.fromBlock)
    throw new EsploraError('expected toBlock >= fromBlock');
  if (res.afterTxid !== undefined && (res.fromBlock !== undefined || res.toBlock !== undefined))
    throw new EsploraError('expected afterTxid without block range');
  if (res.onProgress !== undefined && typeof res.onProgress !== 'function')
    throw new EsploraError(`"onProgress" expected function, got type=${typeof res.onProgress}`);
  return res;
};
const validateHistoryOpts = (opts: TArg<HistoryOpts>): TRet<HistoryOpts> => {
  const res = validateTransfersOpts(opts) as HistoryOpts;
  if (res.order !== undefined && res.order !== 'newest' && res.order !== 'oldest')
    throw new EsploraError(`"order" expected 'newest' | 'oldest', got type=${typeof res.order}`);
  return res as TRet<HistoryOpts>;
};
const throwIfAborted = (signal: AbortSignal | undefined, name: string): void => {
  if (signal && signal.aborted) throw signal.reason ?? new EsploraError(`${name}: aborted`);
};
const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    // An already-aborted signal never fires 'abort' again; without this check
    // the full delay would elapse before the abort is observed.
    if (signal && signal.aborted) return reject(signal.reason ?? new EsploraError('aborted'));
    const done = () => {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
    };
    const onAbort = () => {
      done();
      reject(signal!.reason ?? new EsploraError('aborted'));
    };
    const timer = setTimeout(() => {
      done();
      resolve();
    }, ms);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
  });
// Blockstream/electrs does not emit 500; public frontends shed load with
// 429/502/503/504 responses. GETs back off and retry those instead of aborting.
const RETRYABLE_STATUS = [429, 502, 503, 504];
// WPT records browser network failures as 'Failed to fetch', while undici uses
// 'fetch failed'; proxy HTML or truncated bodies surface as JSON parse errors.
const RETRYABLE_NET = new RegExp(
  'failed to fetch|fetch failed|socket|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EPIPE|' +
    'not valid JSON|in JSON at position|unexpected end of JSON input|' +
    'bad gateway|gateway time-?out|service unavailable',
  'i'
);
const isTransientError = (error: unknown): boolean => {
  if (!(error instanceof Error)) return false;
  if (error.name === 'AbortError') return false; // user aborts are not transient
  if (error instanceof EsploraError)
    return error.status !== undefined && RETRYABLE_STATUS.includes(error.status);
  return RETRYABLE_NET.test(error.message);
};
const RETRY_ATTEMPTS = 8;
// Exponential backoff with jitter, ~125ms first: the tail must outlast a
// rate-limit burst, not just a dropped request.
const retryDelay = (attempt: number): number =>
  Math.min(250 * 2 ** attempt, 8000) * (0.5 + Math.random());
// Maps items through an async fn with at most `concurrency` in flight,
// preserving input order in the result: raw-tx fan-out must not stampede
// rate-limited backends with one giant Promise.all.
async function mapPool<T, R>(
  items: readonly T[],
  fn: (item: T, index: number) => Promise<R>,
  opts: { concurrency: number; signal?: AbortSignal; name: string }
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  // Once any item fails the pool's result is already lost; surviving workers
  // finish their in-flight item but must not keep pulling new ones against a
  // backend that may be the very reason for the failure.
  let failed = false;
  const worker = async () => {
    for (;;) {
      throwIfAborted(opts.signal, opts.name);
      if (failed) return;
      const index = cursor++;
      if (index >= items.length) return;
      try {
        out[index] = await fn(items[index], index);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(opts.concurrency, items.length) }, worker));
  return out;
}
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
type TxMeta = Omit<TxInfo, 'raw'>;
const fixTx = (value: unknown): TxMeta => {
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
const txTransfersRow = (tx: TxMeta, raw: string): TxTransfers => {
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
    raw,
  };
  if (tx.status.blockHash !== undefined) info.blockHash = tx.status.blockHash;
  const res: TxTransfers = { txid: tx.txid, transfers, info };
  if (tx.status.timestamp !== undefined) res.timestamp = tx.status.timestamp;
  if (tx.status.block !== undefined) res.block = tx.status.block;
  return res;
};

/**
 * Esplora-compatible Bitcoin HTTP provider.
 *
 * Runtime transport is caller-provided `fetch`. The repository `test/proxy.ts`
 * bridge is test/dev tooling for serving the wallet/history HTTP subset from Electrum TCP.
 * Transient backend failures (429/5xx, dropped connections) are retried with
 * exponential backoff on GET requests; long-running scans accept `AbortSignal`.
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
  // Single attempt, no retry: used directly by POSTs (sendTx), which could
  // succeed on the backend while the response is lost — blindly
  // re-broadcasting would misreport.
  private async request(path: string, opts: FetchOpts = {}): Promise<FetchResponse> {
    const method = opts.method || 'GET';
    const res = await this.fetch(`${this.url}${path}`, opts);
    if (res.ok) return res;
    const text = await res.text();
    const status = res.statusText ? `${res.status} ${res.statusText}` : `${res.status}`;
    const suffix = text ? `: ${text}` : '';
    throw new EsploraError(`${method} ${path} failed ${status}${suffix}`, {
      status: res.status,
      path,
    });
  }
  // Retrying GET with the body consumed INSIDE the retry scope: a proxy
  // serving an HTML error page with status 200 only fails at res.json(), and
  // that failure must back off like a status failure would.
  private async requestBody(
    path: string,
    kind: 'json' | 'text',
    signal?: AbortSignal
  ): Promise<unknown> {
    const opts: FetchOpts = signal ? { signal } : {};
    for (let attempt = 0; ; attempt++) {
      // Injected transports may ignore an already-aborted signal, so cancel before every attempt.
      throwIfAborted(signal, 'request');
      try {
        const res = await this.request(path, opts);
        return kind === 'json' ? await res.json() : await res.text();
      } catch (error) {
        if (attempt >= RETRY_ATTEMPTS || !isTransientError(error)) throw error;
        await sleep(retryDelay(attempt), signal);
      }
    }
  }
  private getJson(path: string, signal?: AbortSignal): Promise<unknown> {
    return this.requestBody(path, 'json', signal);
  }
  private getText(path: string, signal?: AbortSignal): Promise<string> {
    return this.requestBody(path, 'text', signal) as Promise<string>;
  }
  private addressPath(address: string): string {
    if (typeof address !== 'string') throw new EsploraError('expected address string');
    this.address.decode(address);
    return address;
  }
  private canonicalAddress(address: string): string {
    if (typeof address !== 'string') throw new EsploraError('expected address string');
    return this.address.encode(this.address.decode(address));
  }
  private txHex(txid: string, signal?: AbortSignal): Promise<string> {
    return this.getText(`/tx/${txidPath(txid)}/hex`, signal);
  }
  /**
   * Fetches raw tx hex and verifies it is actually the transaction the txid
   * names, otherwise balances would be computed from whatever transaction the
   * backend chose to serve. `memo` dedupes fetches within one scan: a tx
   * shared by several watched addresses must cost one request, not one per
   * address stream.
   */
  private fetchRawTx(
    txid: string,
    signal?: AbortSignal,
    memo?: Map<string, Promise<string>>
  ): Promise<string> {
    const cached = memo?.get(txid);
    if (cached) return cached;
    const raw = this.txHex(txid, signal).then((rawTx) => {
      parseRawTx(rawTx, txid);
      return rawTx;
    });
    memo?.set(txid, raw);
    return raw;
  }
  /**
   * Pages through Esplora address history newest-first, one transaction at a
   * time. The single owner of cursor pagination: the mempool-aware afterTxid
   * jump, the full-page heuristic and the cursor-loop guard live here.
   */
  private async *addressTxs(
    addr: string,
    afterTxid: string | undefined,
    signal: AbortSignal | undefined
  ): AsyncGenerator<TxMeta, void> {
    // Guards against backends that ignore the chain cursor and keep returning
    // the same page, which would otherwise loop forever.
    const seenCursors = new Set<string>();
    let path = `/address/${addr}/txs`;
    // The first page holds mempool transactions the /txs/chain cursor cannot
    // address, so the cursor is searched there before jumping.
    let cursor = afterTxid;
    for (;;) {
      throwIfAborted(signal, 'history');
      const page = validateArray(await this.getJson(path, signal), 'address.txs').map(fixTx);
      if (!page.length) break;
      let start = 0;
      if (cursor !== undefined) {
        const idx = page.findIndex((tx) => tx.txid === cursor);
        if (idx === -1) {
          seenCursors.add(cursor);
          path = `/address/${addr}/txs/chain/${cursor}`;
          cursor = undefined;
          continue;
        }
        start = idx + 1;
        cursor = undefined;
      }
      for (let i = start; i < page.length; i++) yield page[i];
      const last = page[page.length - 1];
      if (page.length < ESPLORA_PER_PAGE || !last.status.confirmed) break;
      if (seenCursors.has(last.txid)) throw new EsploraError('history: pagination cursor loop');
      seenCursors.add(last.txid);
      path = `/address/${addr}/txs/chain/${last.txid}`;
    }
  }
  private async *historyInner(
    addr: string,
    opts: HistoryOpts,
    rawMemo?: Map<string, Promise<string>>
  ): AsyncGenerator<TxTransfers, void> {
    const signal = opts.signal;
    const newest = (opts.order ?? 'newest') === 'newest';
    const concurrency = opts.concurrency ?? DEFAULT_CONCURRENCY;
    let scannedTxs = 0;
    // Progress percent is exact: address stats already count confirmed and
    // mempool transactions, at the cost of one extra request when listening.
    const totalTxs = opts.onProgress ? (await this.balance(addr, { signal })).txCount : 0;
    const report = (block: number | undefined) => {
      if (!opts.onProgress) return;
      const progress: ScanProgress = {
        scannedTxs,
        totalTxs,
        percent: totalTxs ? Math.min(100, Math.round((scannedTxs / totalTxs) * 100)) : 100,
      };
      if (block !== undefined) progress.currentBlock = block;
      opts.onProgress(progress);
    };
    const net = this;
    const resolve = async function* (chunk: TxMeta[]): AsyncGenerator<TxTransfers, void> {
      const raws = await mapPool(chunk, (tx) => net.fetchRawTx(tx.txid, signal, rawMemo), {
        concurrency,
        signal,
        name: 'history',
      });
      for (let i = 0; i < chunk.length; i++) {
        // An abort between pulls must stop before another already-resolved row escapes.
        throwIfAborted(signal, 'history');
        yield txTransfersRow(chunk[i], raws[i]);
      }
    };
    const buffered: TxMeta[] = [];
    let chunk: TxMeta[] = [];
    let kept = 0;
    for await (const tx of this.addressTxs(addr, opts.afterTxid, signal)) {
      scannedTxs++;
      const block = tx.status.block;
      report(block);
      // Unconfirmed transactions have no block. Keep them in open-ended syncs, but not in fixed
      // historical ranges where callers asked for an exact block interval.
      const inRange =
        block === undefined
          ? opts.toBlock === undefined
          : !(
              (opts.fromBlock !== undefined && block < opts.fromBlock) ||
              (opts.toBlock !== undefined && block > opts.toBlock)
            );
      if (inRange) {
        kept++;
        if (newest) {
          chunk.push(tx);
          if (chunk.length >= ESPLORA_PER_PAGE) {
            for await (const row of resolve(chunk)) yield row;
            chunk = [];
          }
        } else buffered.push(tx);
      }
      if (opts.limit !== undefined && kept >= opts.limit) break;
      // Chain pages are newest-first: once a confirmed transaction drops below
      // fromBlock, everything further is older and the scan can stop.
      if (block !== undefined && opts.fromBlock !== undefined && block < opts.fromBlock) break;
    }
    if (newest) {
      if (chunk.length) for await (const row of resolve(chunk)) yield row;
      return;
    }
    // Esplora address history is newest-first. Reverse the scanned stream instead of sorting by
    // txid; same-block txids have no chronological meaning and sorting them reshuffles page
    // boundaries when callers increase `limit` for address pagination.
    buffered.reverse();
    for (let i = 0; i < buffered.length; i += ESPLORA_PER_PAGE)
      for await (const row of resolve(buffered.slice(i, i + ESPLORA_PER_PAGE))) yield row;
  }
  private async *historyMultiInner(
    addresses: string[],
    opts: HistoryOpts
  ): AsyncGenerator<MultiTxTransfers, void> {
    const newest = (opts.order ?? 'newest') === 'newest';
    // Mempool rows (no block) sort as newest; same-block rows from different
    // addresses have no canonical order and keep stream priority.
    const cmp = (a: TxTransfers, b: TxTransfers): number => {
      const aBlock = a.block ?? Number.MAX_SAFE_INTEGER;
      const bBlock = b.block ?? Number.MAX_SAFE_INTEGER;
      if (aBlock === bBlock) return 0;
      return (aBlock < bBlock ? 1 : -1) * (newest ? 1 : -1);
    };
    // One raw-tx memo for the whole merged scan: a tx touching several watched
    // addresses is discovered by each of their streams but fetched only once.
    const rawMemo = new Map<string, Promise<string>>();
    const streams = addresses.map((address) => this.historyInner(address, opts, rawMemo));
    const heads: (TxTransfers | undefined)[] = new Array(streams.length).fill(undefined);
    // Streams advance one at a time: keeps request bursts bounded, and a k-way
    // merge only ever needs one new head per yield.
    const advance = async (index: number) => {
      const item = await streams[index].next();
      heads[index] = item.done ? undefined : item.value;
    };
    try {
      for (let i = 0; i < streams.length; i++) await advance(i);
      // A transaction touching several watched addresses appears in each of
      // their histories; it must merge into one row, not repeat per address.
      const seen = new Set<string>();
      for (;;) {
        throwIfAborted(opts.signal, 'historyMulti');
        let best = -1;
        for (let i = 0; i < heads.length; i++) {
          if (heads[i] === undefined) continue;
          if (best < 0 || cmp(heads[i]!, heads[best]!) < 0) best = i;
        }
        if (best < 0) return;
        const row = heads[best]!;
        if (!seen.has(row.txid)) {
          seen.add(row.txid);
          const participants = addresses.filter((address) =>
            row.transfers.some((transfer) => transfer.from === address || transfer.to === address)
          );
          // A fallible next read must not suppress the head this stream already resolved.
          yield { ...row, addresses: participants };
        }
        await advance(best);
      }
    } finally {
      await Promise.allSettled(streams.map((stream) => stream.return(undefined)));
    }
  }

  async height(opts: { signal?: AbortSignal } = {}): Promise<number> {
    return validateUint(await this.getText('/blocks/tip/height', opts.signal), 'height');
  }
  async blockInfo(block: number): Promise<BlockInfo> {
    const hash = validateHash(
      await this.getText(`/block-height/${validateUint(block, 'block')}`),
      'block hash'
    );
    const [info, rawTxids] = await Promise.all([
      this.getJson(`/block/${hash}`),
      this.getJson(`/block/${hash}/txids`),
    ]);
    const transactions = validateArray(rawTxids, 'block.txids').map((txid) =>
      validateHash(validateString(txid, 'block.txid'), 'block.txid')
    );
    return fixBlock(info, transactions);
  }
  async fee(target = 2): Promise<bigint> {
    target = validatePositiveInt(target, 'fee target');
    const fees = validateRecord(await this.getJson('/fee-estimates'), 'fee-estimates');
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
  async balance(address: string, opts: { signal?: AbortSignal } = {}): Promise<Balance> {
    const res = validateRecord(
      await this.getJson(`/address/${this.addressPath(address)}`, opts.signal),
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
  async txCount(address: string, opts: { signal?: AbortSignal } = {}): Promise<number> {
    return (await this.balance(address, opts)).txCount;
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
  /**
   * Polls transaction status until it confirms (plus optional extra
   * confirmations). A just-broadcast transaction may briefly be unknown to the
   * backend, so 404 responses keep polling instead of failing.
   */
  async waitForTx(txid: string, opts: WaitTxOpts = {}): Promise<TxStatus> {
    const id = txidPath(txid);
    const options = validateOpts<WaitTxOpts>(opts);
    const confirmations =
      options.confirmations === undefined
        ? 1
        : validatePositiveInt(options.confirmations, 'confirmations');
    const pollIntervalMs =
      options.pollIntervalMs === undefined
        ? 5000
        : validatePositiveInt(options.pollIntervalMs, 'pollIntervalMs');
    if (options.timeoutMs !== undefined) validatePositiveInt(options.timeoutMs, 'timeoutMs');
    const start = Date.now();
    const deadline = async <T>(fn: (signal?: AbortSignal) => Promise<T>): Promise<T> => {
      if (options.timeoutMs === undefined) return fn(options.signal);
      const remaining = options.timeoutMs - (Date.now() - start);
      if (remaining <= 0) throw new EsploraError('waitForTx: timeout');
      const error = new EsploraError('waitForTx: timeout');
      const controller = new AbortController();
      const signal = options.signal
        ? AbortSignal.any([options.signal, controller.signal])
        : controller.signal;
      // Race too: a caller-supplied transport may ignore AbortSignal.
      const expired = sleep(remaining, controller.signal).then(() => {
        controller.abort(error);
        throw error;
      });
      try {
        return await Promise.race([fn(signal), expired]);
      } finally {
        controller.abort();
      }
    };
    for (;;) {
      throwIfAborted(options.signal, 'waitForTx');
      if (options.timeoutMs !== undefined && Date.now() - start >= options.timeoutMs)
        throw new EsploraError('waitForTx: timeout');
      try {
        // Single attempt, no request-level retry: the poll loop is already a
        // retry cadence, and stacking backoff inside it only delays polls.
        const status = await deadline(async (signal) => {
          const res = await this.request(`/tx/${id}/status`, signal ? { signal } : {});
          return fixStatus(await res.json());
        });
        if (status.confirmed && status.block !== undefined) {
          if (confirmations <= 1) return status;
          const height = await deadline((signal) => this.height({ signal }));
          if (height - status.block + 1 >= confirmations) return status;
        }
      } catch (error) {
        // 404: a just-broadcast transaction may not be visible to the backend
        // yet. Transient failures: an outage must not reject a wait that is
        // documented to run until timeoutMs; the next poll retries. Anything
        // else (validation, abort, 4xx) propagates.
        if (!(error instanceof EsploraError && error.status === 404) && !isTransientError(error))
          throw error;
      }
      const remaining =
        options.timeoutMs === undefined ? pollIntervalMs : options.timeoutMs - (Date.now() - start);
      if (remaining <= 0) throw new EsploraError('waitForTx: timeout');
      // Cap the sleep so the next loop checks the deadline before another poll.
      await sleep(Math.min(pollIntervalMs, remaining), options.signal);
    }
  }
  async txInfo(txid: string): Promise<TxInfo> {
    const id = txidPath(txid);
    const [rawInfo, raw] = await Promise.all([this.getJson(`/tx/${id}`), this.txHex(id)]);
    const info = fixTx(rawInfo);
    if (info.txid !== id) throw new EsploraError(`wrong txid, expected ${id} got ${info.txid}`);
    parseRawTx(raw, id);
    return { ...info, raw };
  }
  async unspent(address: string, opts: UnspentOpts = {}): Promise<Unspent> {
    const options = validateScanOpts<UnspentOpts>(opts);
    const items = validateArray(
      await this.getJson(`/address/${this.addressPath(address)}/utxo`, options.signal),
      'address.utxo'
    );
    const outpoints = items.map((value) => {
      const raw = validateRecord(value, 'utxo');
      return {
        txid: validateHash(pickString(raw, 'txid', 'utxo.txid'), 'utxo.txid'),
        index: validateUint(raw.vout, 'utxo.vout'),
      };
    });
    // Several outputs of one funding transaction need its hex only once.
    const txids = [...new Set(outpoints.map((outpoint) => outpoint.txid))];
    const raws = await mapPool(txids, (txid) => this.fetchRawTx(txid, options.signal), {
      concurrency: options.concurrency ?? DEFAULT_CONCURRENCY,
      signal: options.signal,
      name: 'unspent',
    });
    const rawByTxid = new Map<string, string>(txids.map((txid, i) => [txid, raws[i]]));
    const utxo = outpoints.map(({ txid, index }) => ({
      txid,
      index,
      nonWitnessUtxo: hex.decode(rawByTxid.get(txid)!),
    }));
    let balance = _0n;
    for (const input of utxo) {
      const normalized = normalizeInput(input, undefined, undefined, true);
      inputBeforeSign(normalized);
      balance += getPrevOut(normalized).amount;
    }
    return { symbol: 'BTC', decimals: PRECISION, balance, utxo };
  }
  /**
   * Streaming address history. Yields the same {@link TxTransfers} rows as
   * {@link EsploraProvider.transfers}, one at a time, so callers can render or
   * persist rows without waiting for the whole scan.
   *
   * `order: 'newest'` (default) follows Esplora pagination from the mempool
   * backward and streams genuinely: stopping early (break / `limit`) also
   * stops fetching. `order: 'oldest'` yields in transfers() order and must
   * buffer transaction metadata first, since Esplora only pages newest-first;
   * raw transactions still stream in bounded batches.
   * @example
   * ```ts
   * for await (const tx of net.history(address, { limit: 10 })) console.log(tx.txid);
   * ```
   */
  history(address: string, opts: HistoryOpts = {}): AsyncGenerator<TxTransfers, void> {
    const options = validateHistoryOpts(opts);
    return this.historyInner(this.addressPath(address), options);
  }
  /**
   * Merged history across several addresses (HD wallets, watch lists): one
   * txid-deduplicated stream in `order`, k-way merged from per-address
   * {@link EsploraProvider.history} streams. A transaction moving funds
   * between two watched addresses appears once; its `addresses` field lists
   * the watched participants. All options apply to each underlying stream, so
   * `limit` caps rows per address, not the merged total; `afterTxid` is
   * rejected because a chain cursor only exists in one address's history.
   * Same-block rows from different addresses have no canonical order.
   */
  historyMulti(
    addresses: string[],
    opts: HistoryOpts = {}
  ): AsyncGenerator<MultiTxTransfers, void> {
    if (!Array.isArray(addresses) || !addresses.length)
      throw new EsploraError(`"addresses" expected non-empty array, got type=${typeof addresses}`);
    const options = validateHistoryOpts(opts);
    // afterTxid is a single-address cursor: it exists in at most one watched
    // address's history, and fanning it out to the other streams would make
    // their chain-cursor jumps silently drop or misorder those histories.
    if (options.afterTxid !== undefined)
      throw new EsploraError('expected historyMulti without afterTxid');
    // Esplora echoes canonical encodings in transfer rows; re-encode the
    // watched set so participant matching also works for valid but
    // non-canonical inputs (e.g. uppercase bech32 from a QR code).
    const unique = [...new Set(addresses.map((address) => this.canonicalAddress(address)))];
    return this.historyMultiInner(unique, options);
  }
  /**
   * Address history as chronological transfer rows, oldest first. Buffered
   * variant of {@link EsploraProvider.history}; use that to stream rows.
   */
  async transfers(address: string, opts: TransfersOpts = {}): Promise<TxTransfers[]> {
    const options = validateTransfersOpts(opts);
    const txs: TxTransfers[] = [];
    const stream = this.historyInner(this.addressPath(address), { ...options, order: 'oldest' });
    for await (const tx of stream) txs.push(tx);
    return txs;
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
  validateArray(transfers, 'transfers');
  for (let i = 0; i < transfers.length; i++) {
    const tx = validateRecord(transfers[i], `transfers.${i}`);
    validateString(tx.txid, `transfers.${i}.txid`);
    const moves = validateArray(tx.transfers, `transfers.${i}.transfers`);
    validateRecord(tx.info, `transfers.${i}.info`);
    for (let j = 0; j < moves.length; j++) {
      const transfer = validateRecord(moves[j], `transfers.${i}.transfers.${j}`);
      if (transfer.from !== undefined)
        validateString(transfer.from, `transfers.${i}.transfers.${j}.from`);
      if (transfer.to !== undefined)
        validateString(transfer.to, `transfers.${i}.transfers.${j}.to`);
      // Transfer diffs include spends as negative deltas, so this boundary only checks type.
      if (typeof transfer.value !== 'bigint')
        throw new EsploraError(
          `expected transfers.${i}.transfers.${j}.value bigint, got type=${typeof transfer.value}`
        );
    }
  }
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

import { hex } from '@scure/base';
import * as http from 'node:http';
import * as net from 'node:net';
import { pathToFileURL } from 'node:url';
import { Address, OutScript } from '../../src/payment.ts';
import { CompactSizeLen, OP, OPNames, scriptPushLen } from '../../src/script.ts';
import { Transaction } from '../../src/transaction.ts';
import { NETWORK, TEST_NETWORK, sha256, sha256x2, type BTC_NETWORK } from '../../src/utils.ts';

// Generic Electrum TCP to Esplora-like HTTP proxy for development and tests.
// It should work with Electrum protocol servers, but current live coverage is electrs-only:
// Blockstream/electrs and romanz/electrs.
const REGTEST = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef };
const FEE_TARGETS = [...Array.from({ length: 25 }, (_, i) => i + 1), 144, 504, 1008];
const ZERO32 = '00'.repeat(32);
const HEX64 = /^[0-9a-fA-F]{64}$/;
const DEFAULT_ELECTRUM = 'tcp://127.0.0.1:50001';
const DEFAULT_LISTEN = { host: '127.0.0.1', port: 3001 };
const MAX_BLOCK_TXIDS = 100_000;
const ADDRESS_STATS_CONCURRENCY = 32;

type Listen = { host: string; port: number };
type ElectrumUrl = { host: string; port: number };
type Pending = { resolve: (value: unknown) => void; reject: (err: Error) => void };
type Rpc = {
  id?: number;
  method?: string;
  result?: unknown;
  error?: { message?: string } | string;
};
type Output = {
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_type: string;
  scriptpubkey_address?: string;
  value: number;
};
type Verbose = {
  hex?: string;
  blockhash?: string;
  height?: number;
  time?: number;
  confirmations?: number;
};
type History = { tx_hash: string; height: number; key?: string };

export type ProxyOpts = {
  electrum?: string;
  listen?: string | Listen;
  network?: BTC_NETWORK | 'mainnet' | 'testnet' | 'regtest';
};

const usage = `usage: node test/proxy.ts [electrum-url] [--electrum URL] [--listen 127.0.0.1:PORT] [--network mainnet|testnet|regtest]

Examples:
  node test/proxy.ts tcp://127.0.0.1:51001 --listen 127.0.0.1:3001
  node test/proxy.ts --electrum tcp://127.0.0.1:50001 --network mainnet
`;

/**
 * Bench snapshot:
 * `node test/net.bench.ts --runs 5 --busy-limit 25` against a Bitcoin backend,
 * 2026-06. Values are p50 after correctness validation, so proxy caches are warm.
 *
 * | backend           | height |     fee | txCount | txInfo | unspent | transfers |
 * | ----------------- | -----: | ------: | ------: | -----: | ------: | --------: |
 * | direct Esplora    |  0.9ms |   1.0ms |   1.1ms |  1.4ms |   2.1ms |     2.2ms |
 * | Blockstream proxy |  1.3ms |   1.2ms |   1.9ms |  2.0ms |   2.1ms |     2.8ms |
 * | romanz proxy      | 30.7ms |  56.1ms |  46.5ms |  1.7ms |  46.3ms |    46.5ms |
 *
 * | backend           | busyBalance (1001 txs) | busyTransfers25 |
 * | ----------------- | ---------------------: | --------------: |
 * | direct Esplora    |                  1.1ms |          11.3ms |
 * | Blockstream proxy |                268.7ms |         279.2ms |
 * | romanz proxy      |                531.2ms |         559.3ms |
 *
 * Direct Esplora and Blockstream Electrum proxy are effectively local-fast for small wallet
 * calls; romanz raw tx lookup is local-fast, while fee and scripthash calls are tens of
 * milliseconds. Busy-address calls are dominated by exact Esplora parity work: raw Electrum does
 * not expose funded/spent address stats, so the proxy has to inspect address history transactions.
 */

const validateObj = (value: unknown, name: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`expected ${name} object`);
  return value as Record<string, unknown>;
};
const validateNum = (value: unknown, name: string): number => {
  if (typeof value !== 'number' || !Number.isFinite(value))
    throw new Error(`expected ${name} number`);
  return value;
};
const validateStr = (value: unknown, name: string): string => {
  if (typeof value !== 'string') throw new Error(`expected ${name} string`);
  return value;
};
const validateTxid = (value: unknown, name: string): string => {
  // electrs variants differ: Blockstream returns a string, romanz returns { tx_hash }.
  const txid =
    typeof value === 'string' ? value : validateStr(validateObj(value, name).tx_hash, name);
  if (!HEX64.test(txid)) throw new Error(`expected ${name} hex string`);
  return txid.toLowerCase();
};
const isTxidEnd = (err: unknown): boolean => {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    /No tx in position #\d+ in block #\d+/i.test(msg) ||
    // romanz/electrs uses this wording for the normal end-of-block marker.
    /invalid tx_pos \d+ in block at height \d+/i.test(msg) ||
    /transaction.*position.*out of range/i.test(msg)
  );
};
const toSafe = (value: bigint): number => {
  const num = Number(value);
  if (!Number.isSafeInteger(num)) throw new Error(`unsafe integer value=${value}`);
  return num;
};
const u32 = (data: Uint8Array, pos: number): number =>
  // Block header fields such as nonce can exceed signed i32; force JS bitwise output unsigned.
  (data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24)) >>> 0;
const reverseHex = (data: Uint8Array): string => hex.encode(Uint8Array.from(data).reverse());
const reverseTxid = (txid: string): string => txid.match(/../g)!.reverse().join('');
const intKey = (value: number, bytes: number): string => {
  const res = BigInt(value).toString(16);
  const len = bytes * 2;
  if (res.length > len) throw new Error(`integer too large for ${bytes} bytes`);
  return res.padStart(len, '0');
};
const blockHash = (header: Uint8Array): string => reverseHex(sha256x2(header));
const difficulty = (bits: number): number => {
  const exp = bits >>> 24;
  const mantissa = bits & 0x00ffffff;
  return (0xffff * 256 ** (0x1d - 3)) / (mantissa * 256 ** (exp - 3));
};
const isLoopback = (host: string): boolean => host === '127.0.0.1';
const parsePort = (value: string, name: string): number => {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535)
    throw new Error(`wrong ${name} port=${value}`);
  return port;
};
const network = (value: ProxyOpts['network']): BTC_NETWORK => {
  if (!value || value === 'mainnet') return NETWORK;
  if (value === 'testnet') return TEST_NETWORK;
  if (value === 'regtest') return REGTEST;
  return value;
};
const parseElectrum = (value = DEFAULT_ELECTRUM): ElectrumUrl => {
  const text = value.includes('://') ? value : `tcp://${value}`;
  const url = new URL(text);
  if (url.protocol !== 'tcp:') throw new Error(`unsupported Electrum URL protocol=${url.protocol}`);
  return { host: url.hostname || '127.0.0.1', port: parsePort(url.port || '50001', 'Electrum') };
};
const parseListen = (value: ProxyOpts['listen'] = DEFAULT_LISTEN): Listen => {
  if (typeof value !== 'string') {
    if (!isLoopback(value.host)) throw new Error('proxy listener must bind 127.0.0.1');
    return { host: value.host, port: value.port };
  }
  if (/^[0-9]+$/.test(value)) return { host: '127.0.0.1', port: parsePort(value, 'listen') };
  const text = value.includes('://') ? value : `http://${value}`;
  const url = new URL(text);
  if (url.protocol !== 'http:') throw new Error(`unsupported listen protocol=${url.protocol}`);
  if (!isLoopback(url.hostname)) throw new Error('proxy listener must bind 127.0.0.1');
  return { host: '127.0.0.1', port: parsePort(url.port || '3001', 'listen') };
};
const readBody = (req: http.IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 4_000_000) reject(new Error('request body too large'));
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
const cors = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'Content-Type',
};
const send = (
  res: http.ServerResponse,
  status: number,
  body: unknown,
  contentType = 'application/json'
) => {
  res.writeHead(status, { ...cors, 'content-type': contentType });
  if (contentType === 'application/json')
    res.end(
      JSON.stringify(body, (_key, value) => (typeof value === 'bigint' ? toSafe(value) : value))
    );
  else res.end(String(body));
};
const parseTx = (raw: string): Transaction =>
  Transaction.fromRaw(hex.decode(raw), {
    // The bridge handles standard Bitcoin tx versions; only script-shape checks need to be loose.
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
    disableScriptCheck: true,
  });
const bytesHex = (value: Uint8Array | string): string =>
  typeof value === 'string' ? value.toLowerCase() : hex.encode(value);
const opAsm = (op: number): string => {
  if (op >= OP.OP_1 && op <= OP.OP_16) return `OP_PUSHNUM_${op - OP.OP_1 + 1}`;
  const name = OPNames[op];
  if (!name) return `OP_UNKNOWN_${op}`;
  return name.startsWith('OP_') ? name : `OP_${name}`;
};
const scriptAsm = (script: Uint8Array): string => {
  const out = [];
  for (let pos = 0; pos < script.length; ) {
    const op = script[pos++];
    const len = scriptPushLen(op, (bytes) => {
      const value =
        bytes === 1
          ? script[pos]
          : bytes === 2
            ? script[pos] | (script[pos + 1] << 8)
            : u32(script, pos);
      pos += bytes;
      return value;
    });
    if (len !== undefined) {
      const data = script.subarray(pos, pos + len);
      const push = op < OP.PUSHDATA1 ? `OP_PUSHBYTES_${len}` : opAsm(op);
      out.push(`${push}${data.length ? ` ${hex.encode(data)}` : ''}`);
      pos += data.length;
      continue;
    }
    out.push(opAsm(op));
  }
  return out.join(' ');
};
const scriptInfo = (script: Uint8Array): { asm: string; type: string } => {
  let type = script[0] === OP.RETURN ? 'op_return' : 'unknown';
  try {
    const decoded = OutScript.decode(script);
    if (decoded.type === 'pkh') type = 'p2pkh';
    else if (decoded.type === 'sh') type = 'p2sh';
    else if (decoded.type === 'wpkh') type = 'v0_p2wpkh';
    else if (decoded.type === 'wsh') type = 'v0_p2wsh';
    else if (decoded.type === 'tr') type = 'v1_p2tr';
    else if (decoded.type !== 'unknown') type = decoded.type;
  } catch (e) {}
  return { asm: scriptAsm(script), type };
};
const singlePush = (script: Uint8Array): Uint8Array | undefined => {
  if (!script.length) return;
  const op = script[0];
  if (op >= 1 && op < OP.PUSHDATA1 && script.length === op + 1) return script.subarray(1);
  if (op === OP.PUSHDATA1 && script.length === script[1] + 2) return script.subarray(2);
  if (
    op === OP.PUSHDATA2 &&
    script.length >= 3 &&
    script.length === (script[1] | (script[2] << 8)) + 3
  )
    return script.subarray(3);
};
const witnessProgram = (script: Uint8Array): boolean =>
  script.length >= 4 &&
  script.length <= 42 &&
  (script[0] === OP.OP_0 || (script[0] >= OP.OP_1 && script[0] <= OP.OP_16)) &&
  script[1] >= 2 &&
  script[1] <= 40 &&
  script.length === script[1] + 2;

class Electrum {
  private target: ElectrumUrl;
  private socket: net.Socket | undefined;
  private ready: Promise<void> | undefined;
  private buf = '';
  private id = 0;
  private pending = new Map<number, Pending>();
  constructor(target: ElectrumUrl) {
    this.target = target;
  }
  private fail(err: Error) {
    for (const item of this.pending.values()) item.reject(err);
    this.pending.clear();
    this.socket = undefined;
    this.ready = undefined;
    this.buf = '';
  }
  private async connect(): Promise<void> {
    if (this.socket && !this.socket.destroyed) return;
    if (this.ready) return this.ready;
    this.ready = new Promise((resolve, reject) => {
      const socket = net.createConnection(this.target.port, this.target.host);
      this.socket = socket;
      // Electrum RPC sends tiny JSON lines; Nagle can add ~100ms stalls with some servers.
      socket.setNoDelay(true);
      socket.setEncoding('utf8');
      socket.on('connect', resolve);
      socket.on('data', (chunk) => {
        this.buf += chunk;
        for (;;) {
          const pos = this.buf.indexOf('\n');
          if (pos < 0) break;
          const line = this.buf.slice(0, pos).trim();
          this.buf = this.buf.slice(pos + 1);
          if (!line) continue;
          let msg: Rpc;
          try {
            msg = JSON.parse(line);
          } catch (e) {
            continue;
          }
          if (msg.id === undefined) continue;
          const item = this.pending.get(msg.id);
          if (!item) continue;
          this.pending.delete(msg.id);
          if (msg.error)
            item.reject(
              new Error(
                typeof msg.error === 'string' ? msg.error : msg.error.message || 'Electrum error'
              )
            );
          else item.resolve(msg.result);
        }
      });
      socket.on('error', (err) => {
        this.fail(err);
        reject(err);
      });
      socket.on('close', () => this.fail(new Error('Electrum connection closed')));
    });
    return this.ready;
  }
  async call(method: string, ...params: unknown[]): Promise<unknown> {
    await this.connect();
    const socket = this.socket;
    if (!socket || socket.destroyed) throw new Error('Electrum socket is not connected');
    const id = ++this.id;
    const req = `${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`;
    const res = new Promise<unknown>((resolve, reject) =>
      this.pending.set(id, { resolve, reject })
    );
    socket.write(req);
    return res;
  }
  close() {
    this.socket?.end();
  }
}

const createBridge = (rpc: Electrum, netw: BTC_NETWORK) => {
  const addr = Address(netw);
  const rawCache = new Map<string, Promise<string>>();
  const verboseCache = new Map<string, Promise<Verbose | undefined>>();
  const blockByHeight = new Map<number, Promise<Record<string, unknown>>>();
  const blockByHash = new Map<string, Promise<Record<string, unknown>>>();
  const heightByHash = new Map<string, Promise<number>>();
  const blockTxidsByHash = new Map<string, Promise<string[]>>();
  const txHeightById = new Map<string, number>();
  const scriptHash = (script: Uint8Array): string => hex.encode(sha256(script).reverse());
  const addressScriptHash = (address: string): string => {
    const script = OutScript.encode(addr.decode(address) as Parameters<typeof OutScript.encode>[0]);
    return scriptHash(script);
  };
  const addressFromScript = (script: Uint8Array): string | undefined => {
    try {
      return addr.encode(
        OutScript.decode(script) as Parameters<ReturnType<typeof Address>['encode']>[0]
      );
    } catch (e) {
      return;
    }
  };
  const output = (script: Uint8Array, value: bigint): Output => {
    const info = scriptInfo(script);
    const res: Output = {
      scriptpubkey: hex.encode(script),
      scriptpubkey_asm: info.asm,
      scriptpubkey_type: info.type,
      value: toSafe(value),
    };
    const address = addressFromScript(script);
    if (address) res.scriptpubkey_address = address;
    return res;
  };
  const rawTx = (txid: string): Promise<string> => {
    if (!rawCache.has(txid)) {
      rawCache.set(
        txid,
        rpc
          .call('blockchain.transaction.get', txid, false)
          .then((res) => validateStr(res, 'raw tx'))
      );
    }
    return rawCache.get(txid)!;
  };
  const headerInfo = async (height: number): Promise<Record<string, unknown>> => {
    if (!Number.isSafeInteger(height) || height < 0)
      throw new Error(`wrong block height=${height}`);
    if (!blockByHeight.has(height)) {
      const info = rpc.call('blockchain.block.header', height).then((res) => {
        const header = hex.decode(validateStr(res, 'block header'));
        if (header.length !== 80)
          throw new Error(`expected 80-byte block header, got ${header.length}`);
        const hash = blockHash(header);
        const block: Record<string, unknown> = {
          id: hash,
          height,
          version: u32(header, 0),
          previousblockhash: reverseHex(header.subarray(4, 36)),
          merkle_root: reverseHex(header.subarray(36, 68)),
          timestamp: u32(header, 68),
          bits: u32(header, 72),
          nonce: u32(header, 76),
          difficulty: difficulty(u32(header, 72)),
          size: 80,
          weight: 320,
        };
        if (height === 0) delete block.previousblockhash;
        blockByHash.set(hash, Promise.resolve(block));
        heightByHash.set(hash, Promise.resolve(height));
        return block;
      });
      blockByHeight.set(height, info);
    }
    return blockByHeight.get(height)!;
  };
  const height = async () => {
    const res = validateObj(await rpc.call('blockchain.headers.subscribe'), 'headers.subscribe');
    return validateNum(res.height, 'tip height');
  };
  const blockHeight = (hash: string): Promise<number> => {
    const key = hash.toLowerCase();
    if (!heightByHash.has(key)) {
      heightByHash.set(
        key,
        (async () => {
          // Electrum has no hash-to-height index; direct Esplora /block/:hash compatibility has to
          // walk headers until the hash is seen.
          for (let h = await height(); h >= 0; h--) {
            const block = await headerInfo(h);
            if (validateStr(block.id, 'block.id') === key) return h;
          }
          throw new Error(`cannot find block hash=${hash}`);
        })()
      );
    }
    return heightByHash.get(key)!;
  };
  const headerMedianTime = async (height: number): Promise<number> => {
    const start = Math.max(0, height - 10);
    const times = await Promise.all(
      Array.from({ length: height - start + 1 }, async (_, i) =>
        validateNum((await headerInfo(start + i)).timestamp, 'block.timestamp')
      )
    );
    times.sort((a, b) => a - b);
    return times[Math.floor(times.length / 2)];
  };
  const blockTxids = async (block: Record<string, unknown>): Promise<string[]> => {
    const hash = validateStr(block.id, 'block.id').toLowerCase();
    if (!blockTxidsByHash.has(hash)) {
      blockTxidsByHash.set(
        hash,
        (async () => {
          const height = validateNum(block.height, 'block.height');
          const txids = [];
          // Electrum exposes txid-by-position but not block tx count; out-of-range marks the end.
          for (let pos = 0; pos < MAX_BLOCK_TXIDS; pos++) {
            try {
              const txid = validateTxid(
                await rpc.call('blockchain.transaction.id_from_pos', height, pos, false),
                'block txid'
              );
              txHeightById.set(txid, height);
              txids.push(txid);
            } catch (err) {
              if (pos === 0) throw err;
              if (!isTxidEnd(err)) throw err;
              return txids;
            }
          }
          throw new Error(`block txid enumeration exceeded ${MAX_BLOCK_TXIDS}`);
        })()
      );
    }
    return blockTxidsByHash.get(hash)!;
  };
  const blockSizeWeight = async (txids: string[]): Promise<{ size: number; weight: number }> => {
    let size = 80 + CompactSizeLen.encode(txids.length).length;
    let weight = size * 4;
    for (const txid of txids) {
      const raw = await rawTx(txid);
      const tx = parseTx(raw);
      size += raw.length / 2;
      weight += tx.weight;
    }
    return { size, weight };
  };
  const blockInfo = async (hash: string): Promise<Record<string, unknown>> => {
    if (!HEX64.test(hash)) throw new Error(`wrong block hash=${hash}`);
    const block = blockByHash.get(hash.toLowerCase()) || headerInfo(await blockHeight(hash));
    const base = await block;
    const height = validateNum(base.height, 'block.height');
    const txids = await blockTxids(base);
    return {
      ...base,
      ...(await blockSizeWeight(txids)),
      mediantime: await headerMedianTime(height),
      tx_count: txids.length,
    };
  };
  const historyHash = async (hash: string): Promise<History[]> => {
    const res = await rpc.call('blockchain.scripthash.get_history', hash);
    if (!Array.isArray(res)) throw new Error('expected Electrum history array');
    return res.map((item) => {
      const obj = validateObj(item, 'history item');
      const tx_hash = validateStr(obj.tx_hash, 'history tx_hash');
      const height = validateNum(obj.height, 'history height');
      if (height > 0) txHeightById.set(tx_hash, height);
      return {
        tx_hash,
        height,
      };
    });
  };
  const history = async (address: string): Promise<History[]> =>
    historyHash(addressScriptHash(address));
  const verbose = (txid: string): Promise<Verbose | undefined> => {
    if (!verboseCache.has(txid)) {
      verboseCache.set(
        txid,
        rpc.call('blockchain.transaction.get', txid, true).then((res) => {
          if (!res || typeof res === 'string') return;
          const obj = validateObj(res, 'verbose tx');
          return {
            hex: typeof obj.hex === 'string' ? obj.hex : undefined,
            blockhash: typeof obj.blockhash === 'string' ? obj.blockhash : undefined,
            height: typeof obj.height === 'number' ? obj.height : undefined,
            time: typeof obj.time === 'number' ? obj.time : undefined,
            confirmations: typeof obj.confirmations === 'number' ? obj.confirmations : undefined,
          };
        })
      );
    }
    return verboseCache.get(txid)!;
  };
  const txInfo = async (txid: string, height?: number) => {
    const cachedHeight = txHeightById.get(txid);
    const knownHeight = height !== undefined ? height : cachedHeight;
    const [raw, meta] = await Promise.all([rawTx(txid), verbose(txid).catch(() => undefined)]);
    const tx = parseTx(raw);
    const vin = [];
    let inputTotal = 0n;
    for (let i = 0; i < tx.inputsLength; i++) {
      const input = tx.getInput(i);
      const prevId = hex.encode(input.txid!);
      const vout = input.index!;
      const scriptSig = input.finalScriptSig || new Uint8Array();
      const base: Record<string, unknown> = {
        txid: prevId,
        vout,
        scriptsig: hex.encode(scriptSig),
        scriptsig_asm: scriptAsm(scriptSig),
        sequence: input.sequence,
      };
      if (input.finalScriptWitness?.length)
        base.witness = input.finalScriptWitness.map((item) => bytesHex(item));
      if (prevId === ZERO32 && vout === 0xffffffff) {
        vin.push({ ...base, is_coinbase: true });
        continue;
      }
      base.is_coinbase = false;
      const redeem = singlePush(scriptSig);
      if (redeem && witnessProgram(redeem)) base.inner_redeemscript_asm = scriptAsm(redeem);
      const parent = parseTx(await rawTx(prevId));
      const prev = parent.getOutput(vout);
      if (prev.script === undefined || prev.amount === undefined)
        throw new Error(`missing prevout ${prevId}:${vout}`);
      inputTotal += prev.amount;
      vin.push({ ...base, prevout: output(prev.script, prev.amount) });
    }
    const vout = [];
    let outputTotal = 0n;
    for (let i = 0; i < tx.outputsLength; i++) {
      const cur = tx.getOutput(i);
      if (cur.script === undefined || cur.amount === undefined)
        throw new Error(`missing output ${txid}:${i}`);
      outputTotal += cur.amount;
      vout.push(output(cur.script, cur.amount));
    }
    let txHeight = knownHeight;
    if (txHeight === undefined && meta?.height !== undefined) txHeight = meta.height;
    if (txHeight === undefined) {
      const seen = new Set<string>();
      const find = async (script: Uint8Array | undefined) => {
        if (!script) return;
        const hash = scriptHash(script);
        if (seen.has(hash)) return;
        seen.add(hash);
        const item = (await historyHash(hash)).find((i) => i.tx_hash === txid);
        return item?.height;
      };
      for (const out of vout) {
        txHeight = await find(hex.decode(out.scriptpubkey));
        if (txHeight !== undefined) break;
      }
      for (let i = 0; txHeight === undefined && i < tx.inputsLength; i++) {
        const input = tx.getInput(i);
        const prevId = hex.encode(input.txid!);
        if (prevId === ZERO32) continue;
        const parent = parseTx(await rawTx(prevId));
        const prev = parent.getOutput(input.index!);
        txHeight = await find(prev.script);
      }
    }
    if (txHeight === undefined && meta?.blockhash && meta.confirmations && meta.confirmations > 0)
      txHeight = await blockHeight(meta.blockhash);
    // Electrum history uses height=0 for mempool, but block txid enumeration can prove genesis.
    const hasBlockHeight =
      txHeight !== undefined && (txHeight > 0 || (height === undefined && cachedHeight === 0));
    const confirmed = hasBlockHeight || !!(meta?.confirmations && meta.confirmations > 0);
    const status: Record<string, unknown> = { confirmed };
    if (hasBlockHeight) {
      txHeightById.set(txid, txHeight);
      const block = await headerInfo(txHeight);
      status.block_height = txHeight;
      status.block_hash = meta?.blockhash || block.id;
      status.block_time = meta?.time || block.timestamp;
    } else {
      if (meta?.blockhash) status.block_hash = meta.blockhash;
      if (meta?.time) status.block_time = meta.time;
    }
    let weight = (raw.length / 2) * 4;
    try {
      weight = tx.weight;
    } catch (e) {}
    return {
      txid: tx.id,
      version: tx.version,
      locktime: tx.lockTime,
      size: raw.length / 2,
      weight,
      fee: inputTotal > outputTotal ? toSafe(inputTotal - outputTotal) : 0,
      vin,
      vout,
      status,
    };
  };
  const historyKey = async (address: string, item: History): Promise<string> => {
    const tx = await txInfo(item.tx_hash, item.height);
    const keys = [];
    for (let i = 0; i < tx.vout.length; i++) {
      const out = tx.vout[i];
      if (out.scriptpubkey_address !== address) continue;
      keys.push(
        `0${reverseTxid(tx.txid)}${intKey(i, 4)}${intKey(validateNum(out.value, 'output.value'), 8)}`
      );
    }
    for (let i = 0; i < tx.vin.length; i++) {
      const input = validateObj(tx.vin[i], 'input');
      const prev = input.prevout ? validateObj(input.prevout, 'input.prevout') : undefined;
      if (prev?.scriptpubkey_address !== address) continue;
      keys.push(
        `1${reverseTxid(tx.txid)}${intKey(i, 4)}${reverseTxid(validateStr(input.txid, 'input.txid'))}${intKey(validateNum(input.vout, 'input.vout'), 4)}${intKey(validateNum(prev.value, 'input.prevout.value'), 8)}`
      );
    }
    if (!keys.length) throw new Error(`tx ${item.tx_hash} does not touch ${address}`);
    keys.sort();
    return keys[keys.length - 1];
  };
  const sortedHistory = async (address: string) => {
    const txs = await history(address);
    const groups = new Map<number, History[]>();
    for (const tx of txs) {
      if (tx.height <= 0) continue;
      const group = groups.get(tx.height) || [];
      group.push(tx);
      groups.set(tx.height, group);
    }
    await Promise.all(
      Array.from(groups).map(async ([height, group]) => {
        if (group.length < 2) return;
        await Promise.all(group.map(async (tx) => (tx.key = await historyKey(address, tx))));
      })
    );
    return txs.sort((a, b) => {
      const ah = a.height <= 0 ? Number.MAX_SAFE_INTEGER : a.height;
      const bh = b.height <= 0 ? Number.MAX_SAFE_INTEGER : b.height;
      if (ah !== bh) return bh - ah;
      // Blockstream/electrs HTTP scans history DB rows in reverse key order, not block position.
      if (a.key !== undefined && b.key !== undefined && a.key !== b.key)
        return b.key.localeCompare(a.key);
      return a.tx_hash.localeCompare(b.tx_hash);
    });
  };
  const emptyStats = () => ({
    funded_txo_count: 0,
    funded_txo_sum: 0,
    spent_txo_count: 0,
    spent_txo_sum: 0,
    tx_count: 0,
  });
  const addressStats = async (address: string) => {
    const txs = await history(address);
    const chain = emptyStats();
    const mempool = emptyStats();
    for (let i = 0; i < txs.length; i += ADDRESS_STATS_CONCURRENCY) {
      const batch = await Promise.all(
        txs.slice(i, i + ADDRESS_STATS_CONCURRENCY).map(async (item) => {
          const stats = emptyStats();
          const tx = await txInfo(item.tx_hash, item.height);
          stats.tx_count++;
          for (const out of tx.vout) {
            if (out.scriptpubkey_address !== address) continue;
            stats.funded_txo_count++;
            stats.funded_txo_sum += validateNum(out.value, 'output.value');
          }
          for (const input of tx.vin) {
            const prevout = validateObj(input, 'input').prevout;
            if (!prevout) continue;
            const prev = validateObj(prevout, 'input.prevout');
            if (prev.scriptpubkey_address !== address) continue;
            stats.spent_txo_count++;
            stats.spent_txo_sum += validateNum(prev.value, 'input.prevout.value');
          }
          return { confirmed: item.height > 0, stats };
        })
      );
      for (const item of batch) {
        const stats = item.confirmed ? chain : mempool;
        stats.funded_txo_count += item.stats.funded_txo_count;
        stats.funded_txo_sum += item.stats.funded_txo_sum;
        stats.spent_txo_count += item.stats.spent_txo_count;
        stats.spent_txo_sum += item.stats.spent_txo_sum;
        stats.tx_count += item.stats.tx_count;
      }
    }
    return { address, chain_stats: chain, mempool_stats: mempool };
  };
  return {
    async height() {
      return height();
    },
    async blockHash(height: number) {
      const block = await headerInfo(height);
      return validateStr(block.id, 'block.id');
    },
    blockInfo,
    async blockTxids(hash: string) {
      return blockTxids(await blockInfo(hash));
    },
    async fees() {
      const pairs = await Promise.all(
        FEE_TARGETS.map(
          async (target) =>
            [
              target,
              // Some Electrum servers reject long horizons; Esplora fee maps can be sparse.
              await rpc.call('blockchain.estimatefee', target).catch(() => undefined),
            ] as const
        )
      );
      const out: Record<string, number> = {};
      for (const [target, raw] of pairs) {
        if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) continue;
        out[String(target)] = raw * 100_000;
      }
      return out;
    },
    async address(address: string) {
      return addressStats(address);
    },
    async utxo(address: string) {
      const res = await rpc.call('blockchain.scripthash.listunspent', addressScriptHash(address));
      if (!Array.isArray(res)) throw new Error('expected Electrum unspent array');
      return Promise.all(
        res.map(async (item) => {
          const obj = validateObj(item, 'unspent item');
          const height = validateNum(obj.height, 'unspent height');
          const status: Record<string, unknown> = { confirmed: height > 0 };
          if (height > 0) {
            const block = await headerInfo(height);
            status.block_height = height;
            status.block_hash = block.id;
            status.block_time = block.timestamp;
          }
          return {
            txid: validateStr(obj.tx_hash, 'unspent tx_hash'),
            vout: validateNum(obj.tx_pos, 'unspent tx_pos'),
            value: validateNum(obj.value, 'unspent value'),
            status,
          };
        })
      );
    },
    async txs(address: string, last?: string) {
      let txs = await sortedHistory(address);
      if (last) {
        txs = txs.filter((tx) => tx.height > 0);
        const pos = txs.findIndex((tx) => tx.tx_hash === last);
        if (pos < 0) return [];
        txs = txs.slice(pos + 1);
      }
      return Promise.all(txs.slice(0, 25).map((tx) => txInfo(tx.tx_hash, tx.height)));
    },
    txInfo,
    rawTx,
    async broadcast(tx: string) {
      return validateStr(await rpc.call('blockchain.transaction.broadcast', tx), 'broadcast txid');
    },
  };
};

export const startProxy = async (opts: ProxyOpts = {}) => {
  const electrum = parseElectrum(opts.electrum);
  const listen = parseListen(opts.listen);
  const rpc = new Electrum(electrum);
  const bridge = createBridge(rpc, network(opts.network));
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, cors);
        res.end();
        return;
      }
      const url = new URL(req.url || '/', `http://${listen.host}:${listen.port}`);
      const route = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
      if (req.method === 'GET' && route.length === 0) return send(res, 200, usage, 'text/plain');
      if (req.method === 'GET' && route.join('/') === 'blocks/tip/height')
        return send(res, 200, await bridge.height(), 'text/plain');
      if (req.method === 'GET' && route.length === 2 && route[0] === 'block-height')
        return send(res, 200, await bridge.blockHash(Number(route[1])), 'text/plain');
      if (req.method === 'GET' && route.length === 2 && route[0] === 'block')
        return send(res, 200, await bridge.blockInfo(route[1]));
      if (
        req.method === 'GET' &&
        route.length === 3 &&
        route[0] === 'block' &&
        route[2] === 'txids'
      )
        return send(res, 200, await bridge.blockTxids(route[1]));
      if (req.method === 'GET' && route.join('/') === 'fee-estimates')
        return send(res, 200, await bridge.fees());
      if (req.method === 'POST' && route.length === 1 && route[0] === 'tx') {
        try {
          return send(res, 200, await bridge.broadcast((await readBody(req)).trim()), 'text/plain');
        } catch (err) {
          let msg = err instanceof Error ? err.message : String(err);
          // romanz/electrs returns only the Bitcoin Core reject reason; Esplora HTTP includes the
          // RPC code prefix for the same network-rule rejection.
          if (!msg.startsWith('sendrawtransaction RPC error'))
            msg = `sendrawtransaction RPC error -25: ${msg}`;
          return send(res, 400, msg, 'text/plain');
        }
      }
      if (req.method === 'GET' && route.length === 2 && route[0] === 'tx' && route[1])
        return send(res, 200, await bridge.txInfo(route[1]));
      if (req.method === 'GET' && route.length === 3 && route[0] === 'tx' && route[2] === 'hex')
        return send(res, 200, await bridge.rawTx(route[1]), 'text/plain');
      if (req.method === 'GET' && route.length === 2 && route[0] === 'address')
        return send(res, 200, await bridge.address(route[1]));
      if (
        req.method === 'GET' &&
        route.length === 3 &&
        route[0] === 'address' &&
        route[2] === 'utxo'
      )
        return send(res, 200, await bridge.utxo(route[1]));
      if (
        req.method === 'GET' &&
        route.length === 3 &&
        route[0] === 'address' &&
        route[2] === 'txs'
      )
        return send(res, 200, await bridge.txs(route[1]));
      if (
        req.method === 'GET' &&
        route.length === 5 &&
        route[0] === 'address' &&
        route[2] === 'txs' &&
        route[3] === 'chain'
      )
        return send(res, 200, await bridge.txs(route[1], route[4]));
      return send(res, 404, { error: 'not found' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return send(res, 500, { error: msg });
    }
  });
  await new Promise<void>((resolve) => server.listen(listen.port, listen.host, resolve));
  const info = server.address();
  const port = typeof info === 'object' && info ? info.port : listen.port;
  return {
    url: `http://${listen.host}:${port}`,
    electrum,
    close: async () => {
      rpc.close();
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve()))
      );
    },
  };
};

const parseArgs = (args: string[]): ProxyOpts & { help?: boolean } => {
  const opts: ProxyOpts & { help?: boolean } = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--electrum') opts.electrum = args[++i];
    else if (arg === '--listen') opts.listen = args[++i];
    else if (arg === '--network') opts.network = args[++i] as ProxyOpts['network'];
    else if (!opts.electrum) opts.electrum = arg;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return opts;
};

const main = async () => {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(usage);
    return;
  }
  const proxy = await startProxy(opts);
  console.log(`${proxy.url} -> tcp://${proxy.electrum.host}:${proxy.electrum.port}`);
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}

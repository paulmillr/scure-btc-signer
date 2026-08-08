import { it } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import * as mftch from 'micro-ftch';
import { deepStrictEqual, rejects, throws } from 'node:assert';
import { p2sh, p2wpkh, RawTx, Transaction } from '../src/index.ts';
import {
  calcTransfersDiff,
  EsploraError,
  EsploraProvider,
  type ScanProgress,
  type TransfersOpts,
  type TxTransfers,
} from '../src/net.ts';
import { pubECDSA, sha256x2 } from '../src/utils.ts';
import { selectUTXO } from '../src/utxo.ts';
import { default as NET_BASIC } from './vectors/rpc/net_basic.js';
import { default as NET_OLD_HISTORY } from './vectors/rpc/net_old_history.js';
import { default as NET_OLD_UNSPENT } from './vectors/rpc/net_old_unspent.js';
import { default as NET_OLD_UTXO_TX } from './vectors/rpc/net_old_utxo_tx.js';
import { default as NET_PAGINATION_BOUNDARY } from './vectors/rpc/net_pagination_boundary.js';
import { default as NET_TRANSFERS_TAPROOT } from './vectors/rpc/net_transfers_taproot.js';
import { default as NET_UNSPENT } from './vectors/rpc/net_unspent.js';

const NODE_URL = 'https://NODE_URL';
const LIVE_URL = process.env.ESPLORA_URL;

const getKey = (url: string, opt: mftch.FetchOpts) =>
  JSON.stringify({ url: `${NODE_URL}${new URL(url).pathname}`, opt });
const provider = (replayJson: Record<string, string>) =>
  new EsploraProvider(
    LIVE_URL ? fetch : mftch.replayable(fetch, replayJson, { getKey, offline: true }),
    LIVE_URL || NODE_URL
  );
const replayProvider = (replayJson: Record<string, string>) =>
  new EsploraProvider(mftch.replayable(fetch, replayJson, { getKey, offline: true }), NODE_URL);

// Random addresses related to bip341 address
const TAPROOT_ADDR = 'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5';
const TAPROOT_IN = 'bc1qagytqec4jepfun80x5txc7sxv7r8xw9tus7nqy';
const TAPROOT_CHANGE = 'bc1qtq94l500jwkn5hk2cfywracem3ce485k9tkmkl';
const TAPROOT_SPEND = 'bc1qatcvrnwzyduz3xw3h48kceqzcxd9dlmeycn5lx';
const TAPROOT_TX = 'f5d1f75e2f3fcc0afe3210d3ef9b5bde67b6e41bb3be2de3cd4e779c1a92c1f3';
const TAPROOT_SPEND_TX = 'da7f241ff55a774cc32505c7e0956d832b0b3442049e39b8fb77c9476c0af790';
const TAPROOT_RAW =
  '020000000001012a902eca16d6af2ab7d08b63b810b58b0bea33853f55cd3ce1f52edf4194ed7e0400000000feffffff020f2700000000000022512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda3433a4d040000000000160014580b5fd1ef93ad3a5ecac248e1f719dc719a9e9602473044022056db5086d85e669fc8713c376f6e3bb3e8f6d7ee39e7a59792985ee07d9462e202204870556d23909d6adf7b0b9036ddf694a36a73a191d098cdc00e30aac67c36830121028a1b8c1abc60dfc9586903e599d03730a07c0a5aab37e18ace923b1f65e5d062bb050b00';
const TAPROOT_SPEND_RAW =
  '02000000000101f3c1921a9c774ecde32dbeb31be4b667de5b9befd31032fe0acc3f2f5ef7d1f50000000000ffffffff01e325000000000000160014eaf0c1cdc223782899d1bd4f6c6402c19a56ff790140cf6eb054ad61e1835bc4a42a49a0a620bb4b3f30e40de951d35bfba1c66703613db61fa1d41f39bb1d5bab1bc5a1a41d6b5967eb345f1cd347513310feb5169900000000';
const TAPROOT_BLOCK = '00000000000000000002cdd31c32742e176082aeae14f6802867607d05f4acc5';
const TAPROOT_SPEND_BLOCK = '000000000000000000055caa9ffbacae34979ed63363120c5a6ac9f873d21658';
const OLD_ADDR = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const OLD_CHANGE_ADDR = '1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD';
const NET_OLD_HISTORY_WITH_BALANCE = {
  ...NET_OLD_HISTORY,
  [getKey(`${NODE_URL}/address/${OLD_ADDR}`, { headers: {} })]: JSON.stringify({
    address: OLD_ADDR,
    chain_stats: {
      funded_txo_count: 100,
      funded_txo_sum: 16_722_199,
      spent_txo_count: 1,
      spent_txo_sum: 14_293,
      tx_count: 101,
    },
    mempool_stats: {
      funded_txo_count: 0,
      funded_txo_sum: 0,
      spent_txo_count: 0,
      spent_txo_sum: 0,
      tx_count: 0,
    },
  }),
};

const transferSummary = (tx: TxTransfers) => ({
  txid: tx.txid,
  timestamp: tx.timestamp,
  block: tx.block,
  transfers: tx.transfers,
  info: {
    version: tx.info.version,
    lockTime: tx.info.lockTime,
    size: tx.info.size,
    weight: tx.info.weight,
    fee: tx.info.fee,
    blockHash: tx.info.blockHash,
    rawLen: tx.info.raw.length,
  },
});
const pageSummary = (txs: TxTransfers[]) =>
  txs.map((tx) => ({ txid: tx.txid, block: tx.block, timestamp: tx.timestamp }));
const expectedPage = (txs: TxTransfers[], opts: TransfersOpts) => {
  let page = txs;
  if (opts.afterTxid !== undefined) {
    const idx = txs.findIndex((tx) => tx.txid === opts.afterTxid);
    if (idx < 0) throw new Error(`missing cursor ${opts.afterTxid}`);
    page = txs.slice(0, idx);
  } else {
    page = txs.filter((tx) => {
      if (tx.block === undefined) return opts.toBlock === undefined;
      if (opts.fromBlock !== undefined && tx.block < opts.fromBlock) return false;
      if (opts.toBlock !== undefined && tx.block > opts.toBlock) return false;
      return true;
    });
  }
  if (opts.limit !== undefined) page = page.slice(-opts.limit);
  return pageSummary(page);
};
const expectFee = (fee: bigint) => {
  deepStrictEqual(typeof fee, 'bigint');
  if (fee <= 0n) throw new Error(`expected fee > 0, got ${fee}`);
};
const fakeTx = (txid: string) => ({
  txid,
  version: 2,
  locktime: 0,
  vin: [],
  vout: [],
  size: 10,
  weight: 40,
  fee: 0,
  status: { confirmed: false },
});
const fakeRawTx = (index: number) => {
  const tx = new Transaction({ disableScriptCheck: true });
  tx.addOutputAddress(OLD_ADDR, 1n);
  tx.addInput({ txid: new Uint8Array(32), index, finalScriptSig: Uint8Array.of(index & 0xff) });
  return { txid: tx.id, raw: tx.hex };
};
const fakeConfirmedTx = (txid: string) => ({
  txid,
  version: 2,
  locktime: 0,
  vin: [],
  vout: [{ scriptpubkey: '0014e8df018c7e326cc253faac7e46cdc51e68542c42', value: 1 }],
  size: 60,
  weight: 240,
  fee: 0,
  status: {
    confirmed: true,
    block_height: 700_000,
    block_hash: '0'.repeat(64),
    block_time: 1_700_000_000,
  },
});

it('EsploraProvider: real replay for height, block, fees, tx count, tx info', async () => {
  const net = provider(NET_BASIC);
  const height = await net.height();
  deepStrictEqual(typeof height, 'number');
  if (height <= 94_000) throw new Error(`expected height > 94000, got ${height}`);
  deepStrictEqual(await net.blockInfo(1), {
    hash: '00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048',
    number: 1,
    version: 1,
    timestamp: 1231469665000,
    size: 215,
    weight: 860,
    merkleRoot: '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098',
    transactions: ['0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098'],
    parentHash: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    medianTime: 1231469665000,
    nonce: 2573394689,
    bits: 486604799,
    difficulty: 1,
  });
  const fee = await net.fee();
  const longFee = await net.fee(100);
  if (LIVE_URL) {
    expectFee(fee);
    expectFee(longFee);
  } else {
    deepStrictEqual(fee, 5n);
    deepStrictEqual(longFee, 1n);
  }
  deepStrictEqual(await net.balance(TAPROOT_ADDR), {
    symbol: 'BTC',
    decimals: 8,
    balance: 0n,
    txCount: 2,
  });
  deepStrictEqual(await net.txCount(TAPROOT_ADDR), 2);
  deepStrictEqual(await net.txInfo(TAPROOT_TX), {
    txid: TAPROOT_TX,
    version: 2,
    lockTime: 722363,
    size: 234,
    weight: 609,
    fee: 407n,
    inputs: [
      {
        txid: '7eed9441df2ef5e13ccd553f8533ea0b8bb510b8638bd0b72aafd616ca2e902a',
        index: 4,
        prevout: {
          scriptPubKey: '0014ea08b0671596429e4cef35166c7a0667867338ab',
          value: 292320n,
          scriptPubKeyAddress: TAPROOT_IN,
        },
        sequence: 4294967294,
        isCoinbase: false,
      },
    ],
    outputs: [
      {
        scriptPubKey: '512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343',
        value: 9999n,
        scriptPubKeyAddress: TAPROOT_ADDR,
      },
      {
        scriptPubKey: '0014580b5fd1ef93ad3a5ecac248e1f719dc719a9e96',
        value: 281914n,
        scriptPubKeyAddress: TAPROOT_CHANGE,
      },
    ],
    status: {
      confirmed: true,
      block: 722427,
      blockHash: TAPROOT_BLOCK,
      timestamp: 1644384258000,
    },
    raw: TAPROOT_RAW,
  });
});

it('EsploraProvider: real replay for signer-ready unspent outputs', async () => {
  // This exact mainnet UTXO was later spent; keep the signer-ready shape check on the capture.
  const unspent = await replayProvider(NET_UNSPENT).unspent('18qZ8FJho16xzNqQrPouobhyH4hf4uqZrj');
  deepStrictEqual(
    {
      ...unspent,
      utxo: unspent.utxo.map((i) => ({ ...i, nonWitnessUtxo: hex.encode(i.nonWitnessUtxo!) })),
    },
    {
      symbol: 'BTC',
      decimals: 8,
      balance: 16375n,
      utxo: [
        {
          txid: '6ec383579c7eea6bc7e9ba04ed378b0017428d58eae6470d5dcd97c0a9670cab',
          index: 0,
          nonWitnessUtxo:
            '02000000000101bc09c1fb55aefb23df25a84fc667592cd8f8557a39c2dc91fb3fc335ac47d7e60100000000fdffffff02f73f0000000000001976a91455f7a9c7b4c055c1ead052c35cb2e314a1c004f788ace615040000000000160014204709c0ee9427668c8864b12a70c04de0ef658d0247304402203695f71e741ae535b938d3f31b1c97e2e1eb455413a9dd4fc8d1573345f37a1b02204225da7e0cd3201677bef61ea80733933561808e8f2d6446ceeda37c6710491e012103fe23ca7b7b073d3d66e21ba048f39e84c4c8ead53e0ca91b6fed9bfa678bab3c00000000',
        },
      ],
    }
  );
});

it('EsploraProvider: caller metadata makes wrapped unspent selectable', async () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const spend = p2sh(p2wpkh(pubECDSA(privKey)));
  const funding = new Transaction({ disableScriptCheck: true });
  funding.addOutputAddress(spend.address, 20_000n);
  funding.addInput({ txid: new Uint8Array(32), index: 0, finalScriptSig: Uint8Array.of(0) });
  const replay = {
    [getKey(`${NODE_URL}/address/${spend.address}/utxo`, { headers: {} })]: JSON.stringify([
      {
        txid: funding.id,
        vout: 0,
        value: 20_000,
        status: {
          confirmed: true,
          block_height: 1,
          block_hash: '0000000000000000000000000000000000000000000000000000000000000000',
          block_time: 1,
        },
      },
    ]),
    [getKey(`${NODE_URL}/tx/${funding.id}/hex`, { headers: {} })]: funding.hex,
  };
  const net = replayProvider(replay);
  const bare = await net.unspent(spend.address);
  deepStrictEqual(bare.balance, 20_000n);
  throws(
    () => selectUTXO(bare.utxo, [], 'all', { changeAddress: spend.address, feePerByte: 1n }),
    new Error('inputType: sh without redeemScript')
  );
  const spendable = bare.utxo.map((utxo) => ({ ...utxo, redeemScript: spend.redeemScript }));
  const selected = selectUTXO(spendable, [], 'all', {
    changeAddress: spend.address,
    feePerByte: 1n,
  });
  selected.tx.sign(privKey);
  selected.tx.finalize();
  deepStrictEqual(
    {
      selectedFee: selected.fee,
      outputs: selected.outputs,
      txFee: selected.tx.fee,
      txid: selected.tx.id,
      raw: selected.tx.hex,
    },
    {
      selectedFee: 134n,
      outputs: [{ address: spend.address, amount: 19_866n }],
      txFee: 134n,
      txid: '19802b7e5d69d318eab5a415dd7fa1df0911fb4b84e6187bbbd90d8dad083f54',
      raw: '0200000000010190d31ba5c1463f596f544e8d0429bcbd37766abb4abed90f038433d5f72d6400000000001716001479b000887626b294a914501a4cd226b58b235983ffffffff019a4d00000000000017a91427f7b1d97b04ec10e77d4b1527dbb8c9f92c54b5870247304402207921ab51b17bc61e591168fc63bea7d749a0990a986d5c2806f2768d1dac2f8302203e14cfe16f9ba56561cc12b9559b7eb193eebbed21c5a3583a800d12ab2becd10121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f00000000',
    }
  );
});

it('EsploraProvider: real replay for taproot transfers and running balances', async () => {
  const net = provider(NET_TRANSFERS_TAPROOT);
  const transfers = await net.transfers(TAPROOT_ADDR);
  deepStrictEqual(transfers, [
    {
      txid: TAPROOT_TX,
      transfers: [
        { value: 292320n, from: TAPROOT_IN },
        { value: 9999n, to: TAPROOT_ADDR },
        { value: 281914n, to: TAPROOT_CHANGE },
      ],
      info: {
        version: 2,
        lockTime: 722363,
        size: 234,
        weight: 609,
        fee: 407n,
        raw: TAPROOT_RAW,
        blockHash: TAPROOT_BLOCK,
      },
      timestamp: 1644384258000,
      block: 722427,
    },
    {
      txid: TAPROOT_SPEND_TX,
      transfers: [
        { value: 9999n, from: TAPROOT_ADDR },
        { value: 9699n, to: TAPROOT_SPEND },
      ],
      info: {
        version: 2,
        lockTime: 0,
        size: 150,
        weight: 396,
        fee: 300n,
        raw: TAPROOT_SPEND_RAW,
        blockHash: TAPROOT_SPEND_BLOCK,
      },
      timestamp: 1676797797000,
      block: 777311,
    },
  ]);
  deepStrictEqual(calcTransfersDiff(transfers), [
    {
      ...transfers[0],
      balances: { [TAPROOT_IN]: -292320n, [TAPROOT_ADDR]: 9999n, [TAPROOT_CHANGE]: 281914n },
    },
    {
      ...transfers[1],
      balances: {
        [TAPROOT_IN]: -292320n,
        [TAPROOT_ADDR]: 0n,
        [TAPROOT_CHANGE]: 281914n,
        [TAPROOT_SPEND]: 9699n,
      },
    },
  ]);
});

it('EsploraProvider: real replay for empty block-filtered transfer range', async () => {
  deepStrictEqual(
    await provider(NET_TRANSFERS_TAPROOT).transfers(TAPROOT_ADDR, {
      fromBlock: 722428,
      toBlock: 777310,
    }),
    []
  );
});

it('EsploraProvider: real replay for transfer pagination options', async () => {
  const net = provider(NET_OLD_HISTORY);
  const all = await net.transfers(OLD_ADDR);
  const cursorInFirstPage = '5c448fc9f4101f99c063f956bbac6394fc497684e2844ec448461d4c391eba08';
  const cursorInLaterPage = '7231e3eefa4154600f0a2cf75384d0c02c0f34620850b3c7f48a157fb7198e75';
  if (all.length < 100) throw new Error(`expected captured busy history, got ${all.length} txs`);
  const cases: [string, TransfersOpts][] = [
    ['limit', { limit: 7 }],
    ['fromBlock', { fromBlock: 914_000 }],
    ['fromBlock+limit', { fromBlock: 914_000, limit: 5 }],
    ['toBlock', { toBlock: 511_603 }],
    ['toBlock+limit', { toBlock: 754_111, limit: 5 }],
    ['fromBlock+toBlock', { fromBlock: 507_209, toBlock: 511_603 }],
    ['fromBlock+toBlock+limit', { fromBlock: 497_677, toBlock: 754_111, limit: 4 }],
    ['afterTxid', { afterTxid: cursorInLaterPage }],
    ['afterTxid+limit', { afterTxid: cursorInFirstPage, limit: 6 }],
  ];
  const actual: Record<string, ReturnType<typeof pageSummary>> = {};
  const expected: Record<string, ReturnType<typeof pageSummary>> = {};
  for (const [name, opts] of cases) {
    actual[name] = pageSummary(await net.transfers(OLD_ADDR, opts));
    expected[name] = expectedPage(all, opts);
  }
  if (!LIVE_URL)
    deepStrictEqual(
      Object.fromEntries(
        Object.entries(expected).map(([name, page]) => [
          name,
          {
            length: page.length,
            first: page[0],
            last: page[page.length - 1],
            txids: page.map((tx) => tx.txid),
          },
        ])
      ),
      {
        limit: {
          length: 7,
          first: {
            txid: '68f0b228280d9009d993d26b260c57d1a1e3355d689bf960b4436650105f139b',
            block: 943369,
            timestamp: 1775140859000,
          },
          last: {
            txid: '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
            block: 947895,
            timestamp: 1777912259000,
          },
          txids: [
            '68f0b228280d9009d993d26b260c57d1a1e3355d689bf960b4436650105f139b',
            '0cc47f351eaa0ef6cab561075e63aea6bd0e0b9326c77c088663d31ae1dc6720',
            '35b818c2e82267a7d6b4195091b4dac7aa84db750f5612c45197f566036f2f4c',
            'd37f8b9ac13d71d56ef4b3916dc3da9a7b4c9231aaa9c587bc30bee366fc8299',
            '324adb0936873486b22dfd6713bc7ba7597c68980d8c09f239829291fc034bc2',
            'abacbd9edb848d522052a50edb7601e25f72138ee42fff75cab0f539e6d84f22',
            '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
          ],
        },
        fromBlock: {
          length: 27,
          first: {
            txid: 'c04d605093263fca7fd32f593ba0496a651e305ab4b01e56c2571b79d3b02b02',
            block: 914108,
            timestamp: 1757530989000,
          },
          last: {
            txid: '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
            block: 947895,
            timestamp: 1777912259000,
          },
          txids: [
            'c04d605093263fca7fd32f593ba0496a651e305ab4b01e56c2571b79d3b02b02',
            '72b9e8b5fc4ce159043dc7299354d0111e75519e27e6f6303d4b9e6741546b79',
            '5c448fc9f4101f99c063f956bbac6394fc497684e2844ec448461d4c391eba08',
            '1500e34540a114de91606cefc7c930ed22eb091902aa5ed6454a503ffbb96559',
            'be007325ffef1862f5d075422fb3163a9f23970fda6ea6c9a3645ee9a7169bab',
            'a2b3f3f374584182e3fd9d382c449cb927fbe6bc43f0b6329a59d1de95b1bbbb',
            '69bd1bd1fb0ec441d8fe8d18284895d8eaa23a49c10560d71e29652c4184f0e6',
            '20cedf813ef7ae447de9b1ffa23e1aa90f1213ca010ec326e552a7c6c23c4055',
            '373587048225b26dc8eedf056ec2ab7f342b9403300398bb3daab5de8779837b',
            '8ed30b80efc7e984e23b1b417176b720bf6cecb4e7e3504f9157aaa46358bc2e',
            'a9fdb0066e83740d2e337a1d6686ae7969ce6e2239c8c19b3c044525808be0e0',
            '2fd2a1f6bc1c8b2a6b95362bad9d015798fbf5839e273a4a8b7e98b764b2f0fc',
            '744a41915e63a09d5f6e84307d3aa67a1ded316c065bd9513df057bfa835aedc',
            'c48cd16fade256be9c2cc267202ee229f33216b5e21facf593ea539e661fef55',
            '0256ca65c9d33bf8e255b0a3f33b1e8ae110431c2b9b3e9a319b04ac53a03fce',
            'd05806c87ceae62e8f47daafb9fe4842c837fa3f333864cd5a5ec9d2a38cf96b',
            '096ef4f50e537a43beedc54aab617373171578590e0fb99ea5ec406a27a09fc9',
            '96df6ddaa29aa5d8a2dbe71d8a6f2e92cb5adfb254f5d2cb4a2d40db517449cc',
            'e0f2322d869424e2a63b40f76f31b88fe176d7a8562506ada8ee4618f6a06d10',
            '1b47a5c5f1260587bb2c53017aee17d370de84b3716a7f810e46f44b45d9d386',
            '68f0b228280d9009d993d26b260c57d1a1e3355d689bf960b4436650105f139b',
            '0cc47f351eaa0ef6cab561075e63aea6bd0e0b9326c77c088663d31ae1dc6720',
            '35b818c2e82267a7d6b4195091b4dac7aa84db750f5612c45197f566036f2f4c',
            'd37f8b9ac13d71d56ef4b3916dc3da9a7b4c9231aaa9c587bc30bee366fc8299',
            '324adb0936873486b22dfd6713bc7ba7597c68980d8c09f239829291fc034bc2',
            'abacbd9edb848d522052a50edb7601e25f72138ee42fff75cab0f539e6d84f22',
            '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
          ],
        },
        'fromBlock+limit': {
          length: 5,
          first: {
            txid: '35b818c2e82267a7d6b4195091b4dac7aa84db750f5612c45197f566036f2f4c',
            block: 945242,
            timestamp: 1776292901000,
          },
          last: {
            txid: '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
            block: 947895,
            timestamp: 1777912259000,
          },
          txids: [
            '35b818c2e82267a7d6b4195091b4dac7aa84db750f5612c45197f566036f2f4c',
            'd37f8b9ac13d71d56ef4b3916dc3da9a7b4c9231aaa9c587bc30bee366fc8299',
            '324adb0936873486b22dfd6713bc7ba7597c68980d8c09f239829291fc034bc2',
            'abacbd9edb848d522052a50edb7601e25f72138ee42fff75cab0f539e6d84f22',
            '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
          ],
        },
        toBlock: {
          length: 3,
          first: {
            txid: '4ef47f6eb681d5d9fa2f7e16336cd629303c635e8da51e425b76088be9c8744c',
            block: 497677,
            timestamp: 1512456008000,
          },
          last: {
            txid: 'ca38f092f8c148716aed22882b67e6d66099a2dd90e92fa26c4d3dae2c2e08cf',
            block: 511283,
            timestamp: 1519799996000,
          },
          txids: [
            '4ef47f6eb681d5d9fa2f7e16336cd629303c635e8da51e425b76088be9c8744c',
            '1aabe0464403151fdd8fb7edbf231501d15feaaa8c1764839f7078b6f2779c4d',
            'ca38f092f8c148716aed22882b67e6d66099a2dd90e92fa26c4d3dae2c2e08cf',
          ],
        },
        'toBlock+limit': {
          length: 5,
          first: {
            txid: '13a0ff4829305f9c42c952448ca7725c217be7553d63f794e2ab7e7eac673932',
            block: 734272,
            timestamp: 1651339114000,
          },
          last: {
            txid: '7231e3eefa4154600f0a2cf75384d0c02c0f34620850b3c7f48a157fb7198e75',
            block: 754111,
            timestamp: 1663185032000,
          },
          txids: [
            '13a0ff4829305f9c42c952448ca7725c217be7553d63f794e2ab7e7eac673932',
            '573b1c7cb1d9d91817bb21dd6d2a80cfa7c1cb0785216d6ac7ae2c32d2d80cf5',
            '2e94d9c741b58f316bfd61fbf3c7fe59d8d479bb7e525a43fc432c4f1e110948',
            'e38ef5f45a87dd63565f3fb408a32cbab9e107c582d5f90f14fd1f7ae25770c9',
            '7231e3eefa4154600f0a2cf75384d0c02c0f34620850b3c7f48a157fb7198e75',
          ],
        },
        'fromBlock+toBlock': {
          length: 2,
          first: {
            txid: '1aabe0464403151fdd8fb7edbf231501d15feaaa8c1764839f7078b6f2779c4d',
            block: 507209,
            timestamp: 1517545607000,
          },
          last: {
            txid: 'ca38f092f8c148716aed22882b67e6d66099a2dd90e92fa26c4d3dae2c2e08cf',
            block: 511283,
            timestamp: 1519799996000,
          },
          txids: [
            '1aabe0464403151fdd8fb7edbf231501d15feaaa8c1764839f7078b6f2779c4d',
            'ca38f092f8c148716aed22882b67e6d66099a2dd90e92fa26c4d3dae2c2e08cf',
          ],
        },
        'fromBlock+toBlock+limit': {
          length: 4,
          first: {
            txid: '573b1c7cb1d9d91817bb21dd6d2a80cfa7c1cb0785216d6ac7ae2c32d2d80cf5',
            block: 734273,
            timestamp: 1651339717000,
          },
          last: {
            txid: '7231e3eefa4154600f0a2cf75384d0c02c0f34620850b3c7f48a157fb7198e75',
            block: 754111,
            timestamp: 1663185032000,
          },
          txids: [
            '573b1c7cb1d9d91817bb21dd6d2a80cfa7c1cb0785216d6ac7ae2c32d2d80cf5',
            '2e94d9c741b58f316bfd61fbf3c7fe59d8d479bb7e525a43fc432c4f1e110948',
            'e38ef5f45a87dd63565f3fb408a32cbab9e107c582d5f90f14fd1f7ae25770c9',
            '7231e3eefa4154600f0a2cf75384d0c02c0f34620850b3c7f48a157fb7198e75',
          ],
        },
        afterTxid: {
          length: 51,
          first: {
            txid: '4ef47f6eb681d5d9fa2f7e16336cd629303c635e8da51e425b76088be9c8744c',
            block: 497677,
            timestamp: 1512456008000,
          },
          last: {
            txid: 'e38ef5f45a87dd63565f3fb408a32cbab9e107c582d5f90f14fd1f7ae25770c9',
            block: 749608,
            timestamp: 1660602325000,
          },
          txids: [
            '4ef47f6eb681d5d9fa2f7e16336cd629303c635e8da51e425b76088be9c8744c',
            '1aabe0464403151fdd8fb7edbf231501d15feaaa8c1764839f7078b6f2779c4d',
            'ca38f092f8c148716aed22882b67e6d66099a2dd90e92fa26c4d3dae2c2e08cf',
            '6956fc4cedd1bf616decf5239ec375d8d1fd9d1ca96dd25775c089251e551071',
            '2751bc4f834be826a31c0da343ebdf896a4347f263d484be32705fd107958feb',
            '1ad6d151e0976f221c8525a90a75f341d59143f328273d03a745a4a8adf924c7',
            '697ac9c1adad2c7c6fccfff52a0c099d3dd7d3b5f72c0b8aed6d42b4754a53b7',
            'a10bf96de5097265db858409169ef401054c7b44caa33f4c5653fe155ff63921',
            'd556c784af5e8f13fb8be22c42f643e2a45c260154ec21541464678dc8325874',
            '6e8fb5c1f04c72ce93b45e328114379818dcf2be5ebdb20ea97588b545037e9a',
            '59731750d18052aa6c59f61ceb763374d7ee530ecb6f20fb09e3c06d2a8b7ef1',
            'd1097e5086d9ab1f9a71b2ae3be8597339c7966c691cc352eaa5a561e28bfd39',
            '7659a0f9016d86116902b701d95fad6d4709bc9e53bc49fb3e9c5a0e5d86ee27',
            'db13ae38f3ecf2b0739558ab9d9721f8df5e55d3c88f9463aa8f2721b2702543',
            '958da9a9d5f6651699fc497d50c855562e303c0ad4d83491beee4d13e0f9f078',
            '78b8a1f14954269c5744b30598111ffb31cbad7681cf49d229a3853ae49ece52',
            '128d216636f25abdf19480734706bf7d237d57eae7818b7c08c096e937f14d70',
            '05a20280e59dd0d04bee1c13af6cd85cdb0fd62d7da1868c49f3c919426d729d',
            '43e2b15fe87c670c188a5273007a04b658e051203f28eb003cbfb51bc7210410',
            '67546f8c36ea4a37eb8221f90708345d72174471738969d4fc5c25f62f8d8c4a',
            '8e672aa5703c47dc0f622aeedacb6644c4214a12746390cd9e38d2c92b029c5a',
            '2560ccf478011d0cc4d1235a29b38cfcd75f9620f7b5201b018185c045b1c1ab',
            'aa0f6f40a6d31de9559efeb4808f0cb7fb328f02cda9a57395240e4a7cd31a29',
            '63024ca8ac6be3f3ce08e3d246c1a70d48659264006f70e5a5085984f32515dd',
            '83a06f47ee762736a59564f19cc36b078850732f1ec4a795237f11af6151accc',
            'b89dcfce2cd7929ccdf4fc597e551b6bf43441571dc09e465d09ab0a854ac997',
            'b2ddc82d52eb17a23e9890db550c2909667542a7d9a76ebef6e000a01d224799',
            '41053d9ffc5bcd11e00c7a9f7404af59a7c3d2c45a80b11f8cdff29fbed4b97a',
            '79fe74c327590f9d233574642833db9003d9c9daa0f95abf1493db4f2c2b04eb',
            'f09b21498067bb902e626c6e5d58b8c7fa8b80cb3298a1866e2d6da8b4e71c5f',
            'cb6de7dc1bb280efb912e1dc1b068deb42b90f9f3586ce544cfa0353aaaee8ce',
            '6ca026083430e1aa1a88152189e77e0d4eb1e5bd976bcf720e17fbbf503afa63',
            'a710478702db12c062028666e3eda1cedf0f0f64dc2d32ed673248d608da8828',
            '39d2d6f1ca121bf64b2cc2c24e68a690c5bca4a5b1aeb3f4e4acab5228727ed3',
            '519e5b78a81006a88a8f8794ecba9d2500eaceb0a4c2509c1b042fee857a2ee9',
            '05c5cfe64f3b9061a18c56b595234a7537ff71e2e1ba6580c21035b7cab2fc77',
            '8f48b4f09df0ce578189d76550b2bfa9c947021ea670bc200ed792869db1506b',
            'e499f1857f57fd76c1e22711a2cfcbf868d4104edee8943be73cf6f2fb9907e3',
            'b3fd5a6302e308bde661af8609c1238a0f7805c519654bcfe1470ff5451e9eae',
            '5a3b64731d6d8e92867051ac167b26333b89a40b0a6672adb62dd8441e20460d',
            '1c080b3654194280ece3046ff5cc9b9d07175a5fbeb9e14d157d693d1b7b2309',
            '1722ab7939b968b314289217bf3feb57da41457e1ca72d98f918213f2937b527',
            '11e4e5f76ea3e8a69c5117abcde5a5240d79d5420d4c4c3c74a3a7b9a3d424c0',
            '46d0b17dec2d3518c9b8e9a1e86107c7207baef6279aaf751dcaaa9f4fc637ff',
            'c9933a04e0b30524e3ff3c56ca9171ed61a74ecc476181835777cf03b841645d',
            '5950c074b07c3d511e9022de7b692eb394737e7a85151cc5bd82b05b30ed23bf',
            '7be2c740bb47953fcd1083424f5dcf0f3f38b1b3b8a145b6d9f1d8e9ece9a656',
            '13a0ff4829305f9c42c952448ca7725c217be7553d63f794e2ab7e7eac673932',
            '573b1c7cb1d9d91817bb21dd6d2a80cfa7c1cb0785216d6ac7ae2c32d2d80cf5',
            '2e94d9c741b58f316bfd61fbf3c7fe59d8d479bb7e525a43fc432c4f1e110948',
            'e38ef5f45a87dd63565f3fb408a32cbab9e107c582d5f90f14fd1f7ae25770c9',
          ],
        },
        'afterTxid+limit': {
          length: 6,
          first: {
            txid: '1eb49e7364991b1881bc7b799f5f0d6ed06084679d4bb344f2f763ffe48dbd86',
            block: 899815,
            timestamp: 1749071891000,
          },
          last: {
            txid: '72b9e8b5fc4ce159043dc7299354d0111e75519e27e6f6303d4b9e6741546b79',
            block: 914431,
            timestamp: 1757726994000,
          },
          txids: [
            '1eb49e7364991b1881bc7b799f5f0d6ed06084679d4bb344f2f763ffe48dbd86',
            'eea60b41e53fd0f14784fd64503ca1e8895df92b0eafcf98e7e99f222ef9550a',
            '1341f5f7db5fba46aa43fe1015e2d060d2a57c3aa7694e7fdc9e585f1f924203',
            '942f33a1647d5b714afb7b2bf08f0ed8d40961ef97cd6b04341484e64a96c982',
            'c04d605093263fca7fd32f593ba0496a651e305ab4b01e56c2571b79d3b02b02',
            '72b9e8b5fc4ce159043dc7299354d0111e75519e27e6f6303d4b9e6741546b79',
          ],
        },
      }
    );
  deepStrictEqual(actual, expected);
});

it('EsploraProvider: transfer limit keeps already-loaded latest page stable', async () => {
  const rawTxs = Array.from({ length: 50 }, (_, i) => fakeRawTx(i));
  const txids = rawTxs.map((i) => i.txid);
  const replay: Record<string, string> = Object.fromEntries(
    rawTxs.map(({ txid, raw }) => [getKey(`${NODE_URL}/tx/${txid}/hex`, { headers: {} }), raw])
  );
  replay[getKey(`${NODE_URL}/address/${OLD_ADDR}/txs`, { headers: {} })] = JSON.stringify(
    txids.slice(0, 25).map(fakeConfirmedTx)
  );
  replay[getKey(`${NODE_URL}/address/${OLD_ADDR}/txs/chain/${txids[24]}`, { headers: {} })] =
    JSON.stringify(txids.slice(25).map(fakeConfirmedTx));
  const net = replayProvider(replay);
  const latest25 = (await net.transfers(OLD_ADDR, { limit: 25 })).map((i) => i.txid);
  const latest50 = (await net.transfers(OLD_ADDR, { limit: 50 })).map((i) => i.txid);
  deepStrictEqual(latest50.slice(-25), latest25);
});

it('EsploraProvider: captured transfer pages compose without losing boundary transactions', async () => {
  const net = provider({ ...NET_OLD_HISTORY, ...NET_PAGINATION_BOUNDARY });
  const all = await net.transfers(OLD_ADDR);
  const check = async (total: number, part: number) => {
    const expected = all.slice(-total);
    const latest = await net.transfers(OLD_ADDR, { limit: total });
    const newest = await net.transfers(OLD_ADDR, { limit: part });
    const older = await net.transfers(OLD_ADDR, { afterTxid: newest[0].txid, limit: part });
    const merged = [...older, ...newest];
    deepStrictEqual(
      {
        expected: expected.length,
        latest: latest.length,
        newest: newest.length,
        older: older.length,
        latestTxids: latest.map((tx) => tx.txid),
        mergedTxids: merged.map((tx) => tx.txid),
        merged,
      },
      {
        expected: total,
        latest: total,
        newest: part,
        older: part,
        latestTxids: expected.map((tx) => tx.txid),
        mergedTxids: expected.map((tx) => tx.txid),
        merged: latest,
      }
    );
  };
  await check(50, 25);
  await check(60, 30);
});

it('EsploraProvider: transfers afterTxid follows Esplora cursors', async () => {
  const rawTxs = Array.from({ length: 99 }, (_, i) => fakeRawTx(i));
  const txids = rawTxs.map((i) => i.txid);
  const tx = (txid: string, i: number) => ({
    txid,
    version: 2,
    locktime: 0,
    vin: [],
    vout: [{ scriptpubkey: '0014e8df018c7e326cc253faac7e46cdc51e68542c42', value: 1 }],
    size: 60,
    weight: 240,
    fee: 0,
    status:
      i < 50
        ? { confirmed: false }
        : {
            confirmed: true,
            block_height: 700_000,
            block_hash: '0'.repeat(64),
            block_time: 1_700_000_000,
          },
  });
  const replay: Record<string, string> = Object.fromEntries(
    rawTxs.map(({ txid, raw }) => [getKey(`${NODE_URL}/tx/${txid}/hex`, { headers: {} }), raw])
  );
  replay[getKey(`${NODE_URL}/address/${OLD_ADDR}/txs`, { headers: {} })] = JSON.stringify(
    txids.slice(0, 75).map(tx)
  );
  replay[getKey(`${NODE_URL}/address/${OLD_ADDR}/txs/chain/${txids[74]}`, { headers: {} })] =
    JSON.stringify(txids.slice(75).map(tx));
  const net = replayProvider(replay);
  const first = await net.transfers(OLD_ADDR, { limit: 25 });
  const second = await net.transfers(OLD_ADDR, { afterTxid: txids[24], limit: 25 });
  const third = await net.transfers(OLD_ADDR, { afterTxid: txids[49], limit: 25 });
  const fourth = await net.transfers(OLD_ADDR, { afterTxid: txids[74], limit: 25 });
  await rejects(
    () => net.transfers(OLD_ADDR, { afterTxid: txids[24], fromBlock: 1 }),
    new EsploraError('expected afterTxid without block range')
  );
  await rejects(
    () => net.transfers(OLD_ADDR, { afterTxid: txids[24], toBlock: 1 }),
    new EsploraError('expected afterTxid without block range')
  );
  deepStrictEqual(
    {
      firstTxids: first.map((i) => i.txid),
      secondTxids: second.map((i) => i.txid),
      thirdTxids: third.map((i) => i.txid),
      fourthTxids: fourth.map((i) => i.txid),
    },
    {
      firstTxids: txids.slice(0, 25).reverse(),
      secondTxids: txids.slice(25, 50).reverse(),
      thirdTxids: txids.slice(50, 75).reverse(),
      fourthTxids: txids.slice(75).reverse(),
    }
  );
});

it('EsploraProvider: archived replay for old unspent vector', async () => {
  const net = provider(NET_OLD_UNSPENT);
  const feePerByte = await net.fee();
  const unspent = await net.unspent(OLD_ADDR);
  deepStrictEqual(
    {
      ...unspent,
      utxo: [],
    },
    {
      symbol: 'BTC',
      decimals: 8,
      balance: 16707906n,
      utxo: [],
    }
  );
  const selected = selectUTXO(unspent.utxo, [], 'all', {
    changeAddress: OLD_CHANGE_ADDR,
    feePerByte,
  });
  if (LIVE_URL) {
    expectFee(selected.fee);
    deepStrictEqual(selected.tx.fee, selected.fee);
    deepStrictEqual(selected.outputs, [
      { address: OLD_CHANGE_ADDR, amount: unspent.balance - selected.fee },
    ]);
  } else {
    deepStrictEqual(hex.encode(selected.tx.toPSBT()), NET_OLD_UTXO_TX);
  }
});

it('EsploraProvider: archived replay for old history vector', async () => {
  const net = provider(NET_OLD_HISTORY_WITH_BALANCE);
  const [balance, transfers] = await Promise.all([net.balance(OLD_ADDR), net.transfers(OLD_ADDR)]);
  const diff = calcTransfersDiff(transfers);
  let lastBlock = 0;
  for (const tx of diff) {
    if (tx.block === undefined) throw new Error(`transfers: expected confirmed tx ${tx.txid}`);
    if (tx.block < lastBlock) throw new Error(`transfers: wrong order at ${tx.txid}`);
    lastBlock = tx.block;
    const running = tx.balances[OLD_ADDR] || 0n;
    if (running < 0n) throw new Error(`calcTransfersDiff: wrong order at ${tx.txid}`);
  }
  deepStrictEqual(
    {
      count: transfers.length,
      balance,
      first: transferSummary(transfers[0]),
      last: transferSummary(transfers[transfers.length - 1]),
      finalBalance: diff[diff.length - 1].balances[OLD_ADDR],
    },
    {
      count: 101,
      balance: {
        symbol: 'BTC',
        decimals: 8,
        balance: 16_707_906n,
        txCount: 101,
      },
      first: {
        txid: '4ef47f6eb681d5d9fa2f7e16336cd629303c635e8da51e425b76088be9c8744c',
        timestamp: 1512456008000,
        block: 497677,
        transfers: [
          { value: 70000n, from: 'bc1qf6lcjztqwv9kmkk7xclgdd5khmhhhfwkfxqy48' },
          { value: 16945n, from: 'bc1qzhayf65p2j4h3pfw22aujgr5w42xfqzx5uvddt' },
          { value: 14293n, to: OLD_ADDR },
          {
            value: 70000n,
            to: 'bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9',
          },
        ],
        info: {
          version: 1,
          lockTime: 0,
          size: 383,
          weight: 881,
          fee: 2652n,
          blockHash: '0000000000000000003cf6561bf9c83e72dc202e6af301b5147ae8ceda1c96a9',
          rawLen: 766,
        },
      },
      last: {
        txid: '7376089ab5408fa2f66c780bdd6bfc3638431453e785c60917ba8e0d2591d4a6',
        timestamp: 1777912259000,
        block: 947895,
        transfers: [
          { value: 543263n, from: 'bc1qkh08tl5jauawjdpdkc523nut89fca7w8l3c3n4' },
          { value: 100000n, to: OLD_ADDR },
          { value: 443120n, to: 'bc1qkh08tl5jauawjdpdkc523nut89fca7w8l3c3n4' },
        ],
        info: {
          version: 2,
          lockTime: 0,
          size: 223,
          weight: 562,
          fee: 143n,
          blockHash: '0000000000000000000215d07246061ca069c7389f1125e224e739e701159ee7',
          rawLen: 446,
        },
      },
      finalBalance: 16707906n,
    }
  );
});

it('EsploraProvider: archived replay for old filtered history vector', async () => {
  const transfers = await provider(NET_OLD_HISTORY).transfers(OLD_ADDR, {
    fromBlock: 507209,
    // Ranges are inclusive here; the old Electrum test treated block 511604 as the far edge.
    toBlock: 511603,
  });
  deepStrictEqual(transfers.map(transferSummary), [
    {
      txid: '1aabe0464403151fdd8fb7edbf231501d15feaaa8c1764839f7078b6f2779c4d',
      timestamp: 1517545607000,
      block: 507209,
      transfers: [
        { value: 70365n, from: 'bc1qhrrj9fnpsfjgl5xljd37p6v68dlld3jez5vrcj' },
        { value: 65595n, from: 'bc1q3nz6c72nnxjgl2mvsmf4h3qapkcjckqxky4at8' },
        { value: 65432n, from: 'bc1quhzrpn8hh7uvpvnr49svha5g2rc5q5fn4srlyj' },
        { value: 55432n, from: 'bc1qmtrqw8fytrztnhe0vcm9hspzjkn7vhlj55jwkw' },
        { value: 53949n, from: 'bc1q438rspr2q4faxc2t4wed2v6zljzdc67np5xqf3' },
        { value: 14293n, from: OLD_ADDR },
        { value: 290000n, to: '17tqfbMfpEdycyor5yJN2xCGtUtGs7MtrS' },
      ],
      info: {
        version: 1,
        lockTime: 0,
        size: 939,
        weight: 1809,
        fee: 35066n,
        blockHash: '0000000000000000005a71f8e328807aff7d28ac200d5ebe8ff3f51196d7c37c',
        rawLen: 1878,
      },
    },
    {
      txid: 'ca38f092f8c148716aed22882b67e6d66099a2dd90e92fa26c4d3dae2c2e08cf',
      timestamp: 1519799996000,
      block: 511283,
      transfers: [
        { value: 1053982n, from: '3NZiodMiB8K8fzgCY1itQ3CxEYwDxgdfpe' },
        { value: 1034142n, to: 'bc1qgtxp00l6vaya6shzn3ykajguy6zns3gve9dgzn' },
        { value: 10000n, to: OLD_ADDR },
      ],
      info: {
        version: 2,
        lockTime: 511282,
        size: 246,
        weight: 654,
        fee: 9840n,
        blockHash: '0000000000000000005d19f53a02f5619b32bcda4c80cae3fa09ec40f136afef',
        rawLen: 492,
      },
    },
  ]);
});

it('EsploraProvider: sendTx reports backend rejection', async () => {
  const body = 'sendrawtransaction RPC error -25: bad-txns-inputs-missingorspent';
  const calls: unknown[] = [];
  const fetch = async (url: string, opts = {}) => {
    calls.push({ url, opts });
    return {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      json: async () => ({ error: body }),
      text: async () => body,
    };
  };
  await rejects(
    () => new EsploraProvider(fetch, NODE_URL).sendTx(TAPROOT_RAW),
    new EsploraError(`POST /tx failed 400 Bad Request: ${body}`)
  );
  deepStrictEqual(calls, [
    {
      url: `${NODE_URL}/tx`,
      opts: { method: 'POST', headers: { 'content-type': 'text/plain' }, body: TAPROOT_RAW },
    },
  ]);
});

it('EsploraProvider: rejects mismatched tx metadata and raw txids', async () => {
  const wrong = '1'.repeat(64);
  await rejects(
    () =>
      replayProvider({
        [getKey(`${NODE_URL}/tx/${TAPROOT_TX}`, { headers: {} })]: JSON.stringify(fakeTx(wrong)),
        [getKey(`${NODE_URL}/tx/${TAPROOT_TX}/hex`, { headers: {} })]: TAPROOT_RAW,
      }).txInfo(TAPROOT_TX),
    new EsploraError(`wrong txid, expected ${TAPROOT_TX} got ${wrong}`)
  );
  await rejects(
    () =>
      replayProvider({
        [getKey(`${NODE_URL}/address/${OLD_ADDR}/txs`, { headers: {} })]: JSON.stringify([
          fakeTx(TAPROOT_TX),
        ]),
        [getKey(`${NODE_URL}/tx/${TAPROOT_TX}/hex`, { headers: {} })]: TAPROOT_SPEND_RAW,
      }).transfers(OLD_ADDR),
    new EsploraError(`wrong raw txid, expected ${TAPROOT_TX} got ${TAPROOT_SPEND_TX}`)
  );
});

it('EsploraProvider: validates broadcast result txid', async () => {
  const fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({}),
    text: async () => 'not-a-txid',
  });
  await rejects(
    () => new EsploraProvider(fetch, NODE_URL).sendTx(TAPROOT_RAW),
    new EsploraError('expected broadcast txid hex string')
  );
});

it('EsploraProvider: request preserves transport and body errors', async () => {
  const fetchError = new Error('network down');
  await rejects(
    () =>
      new EsploraProvider(async () => {
        throw fetchError;
      }, NODE_URL).height(),
    fetchError
  );
  const textError = new Error('body unavailable');
  await rejects(
    () =>
      new EsploraProvider(
        async () => ({
          ok: false,
          status: 500,
          json: async () => ({}),
          text: async () => {
            throw textError;
          },
        }),
        NODE_URL
      ).height(),
    textError
  );
});

it('EsploraProvider: balance parses bigint amount fields without bigint HTTP values', async () => {
  const fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      chain_stats: {
        funded_txo_sum: '9007199254740993',
        spent_txo_sum: '9007199254740991',
        tx_count: 2,
      },
      mempool_stats: {
        funded_txo_sum: 3,
        spent_txo_sum: 1,
        tx_count: 1,
      },
    }),
    text: async () => '',
  });
  deepStrictEqual(await new EsploraProvider(fetch, NODE_URL).balance(TAPROOT_ADDR), {
    symbol: 'BTC',
    decimals: 8,
    balance: 4n,
    txCount: 3,
  });
});

// Plain path-routed fetch mock for the streaming/retry/abort tests; the
// replay-based tests above keep exercising the captured mainnet vectors.
type MockRes = {
  ok: boolean;
  status: number;
  statusText?: string;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
};
const okRes = (body: unknown): MockRes => ({
  ok: true,
  status: 200,
  json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
  text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
});
const errRes = (status: number, statusText = ''): MockRes => ({
  ok: false,
  status,
  statusText,
  json: async () => ({}),
  text: async () => '',
});
const routed =
  (routes: Record<string, unknown>, calls: string[] = []) =>
  async (url: string, opts: { method?: string } = {}): Promise<MockRes> => {
    const path = url.slice(NODE_URL.length);
    calls.push(`${opts.method || 'GET'} ${path}`);
    if (!(path in routes)) return errRes(404, 'Not Found');
    return okRes(routes[path]);
  };
const collect = async <T>(gen: AsyncGenerator<T, void>): Promise<T[]> => {
  const out: T[] = [];
  for await (const item of gen) out.push(item);
  return out;
};

it('EsploraProvider: retries transient GET failures', async () => {
  let calls = 0;
  const fetch = async () => (++calls < 3 ? errRes(503, 'Service Unavailable') : okRes('123'));
  deepStrictEqual(await new EsploraProvider(fetch, NODE_URL).height(), 123);
  deepStrictEqual(calls, 3);
});

it('EsploraProvider: retries browser fetch failures', async () => {
  let calls = 0;
  const fetch = async () => {
    if (++calls === 1) throw new TypeError('Failed to fetch');
    return okRes({ '2': 5 });
  };
  deepStrictEqual(await new EsploraProvider(fetch, NODE_URL).fee(), 5n);
  deepStrictEqual(calls, 2);
});

it('EsploraProvider: retries transient body-parse failures', async () => {
  // A proxy can serve an HTML error page with status 200; the failure only
  // surfaces at res.json() and must back off like a status failure.
  let calls = 0;
  const html: MockRes = {
    ok: true,
    status: 200,
    json: async () => {
      throw new SyntaxError('Unexpected token \'<\', "<html>" is not valid JSON');
    },
    text: async () => '<html>',
  };
  const truncated: MockRes = {
    ...html,
    json: async () => {
      throw new SyntaxError('Unexpected end of JSON input');
    },
  };
  const fetch = async () => (++calls === 1 ? html : calls === 2 ? truncated : okRes({ '2': 5 }));
  deepStrictEqual(await new EsploraProvider(fetch, NODE_URL).fee(), 5n);
  deepStrictEqual(calls, 3);
});

it('EsploraProvider: waitForTx aborts promptly during the poll sleep', async () => {
  // A signal aborted before sleep() is entered fires no 'abort' event; the
  // upfront aborted check must reject instead of waiting out pollIntervalMs.
  const controller = new AbortController();
  const reason = new Error('cancel wait');
  const fetch = async (): Promise<MockRes> => {
    controller.abort(reason);
    return okRes({ confirmed: false });
  };
  const net = new EsploraProvider(fetch, NODE_URL);
  const start = Date.now();
  await rejects(
    () => net.waitForTx(TAPROOT_TX, { pollIntervalMs: 60_000, signal: controller.signal }),
    reason
  );
  deepStrictEqual(Date.now() - start < 5_000, true);
});

it('EsploraProvider: does not retry non-transient or POST failures', async () => {
  let getCalls = 0;
  const badRequest = async () => {
    getCalls++;
    return errRes(400, 'Bad Request');
  };
  await rejects(() => new EsploraProvider(badRequest, NODE_URL).height());
  deepStrictEqual(getCalls, 1);
  let postCalls = 0;
  const overloaded = async () => {
    postCalls++;
    return errRes(503, 'Service Unavailable');
  };
  await rejects(() => new EsploraProvider(overloaded, NODE_URL).sendTx(TAPROOT_RAW));
  deepStrictEqual(postCalls, 1);
});

it('EsploraProvider: errors carry HTTP status and path', async () => {
  const net = new EsploraProvider(async () => errRes(404, 'Not Found'), NODE_URL);
  await rejects(
    () => net.height(),
    (error: unknown) => {
      deepStrictEqual(error instanceof EsploraError, true);
      deepStrictEqual((error as EsploraError).status, 404);
      deepStrictEqual((error as EsploraError).path, '/blocks/tip/height');
      return true;
    }
  );
});

it('EsploraProvider: unspent fetches each funding transaction once', async () => {
  const funding = new Transaction({ disableScriptCheck: true });
  funding.addOutputAddress(OLD_ADDR, 1n);
  funding.addOutputAddress(OLD_ADDR, 2n);
  funding.addInput({ txid: new Uint8Array(32), index: 0, finalScriptSig: Uint8Array.of(0) });
  const other = fakeRawTx(9);
  const calls: string[] = [];
  const fetch = routed(
    {
      [`/address/${OLD_ADDR}/utxo`]: [
        { txid: funding.id, vout: 0, value: 1, status: { confirmed: true } },
        { txid: funding.id, vout: 1, value: 2, status: { confirmed: true } },
        { txid: other.txid, vout: 0, value: 1, status: { confirmed: true } },
      ],
      [`/tx/${funding.id}/hex`]: funding.hex,
      [`/tx/${other.txid}/hex`]: other.raw,
    },
    calls
  );
  const unspent = await new EsploraProvider(fetch, NODE_URL).unspent(OLD_ADDR);
  deepStrictEqual(unspent.balance, 4n);
  deepStrictEqual(unspent.utxo.length, 3);
  deepStrictEqual(calls.filter((call) => call === `GET /tx/${funding.id}/hex`).length, 1);
});

it('EsploraProvider: unspent bounds raw-tx fetch concurrency', async () => {
  const rawTxs = Array.from({ length: 10 }, (_, i) => fakeRawTx(i));
  const byTxid = new Map(rawTxs.map(({ txid, raw }) => [txid, raw]));
  let inFlight = 0;
  let maxInFlight = 0;
  const fetch = async (url: string): Promise<MockRes> => {
    const path = url.slice(NODE_URL.length);
    if (path === `/address/${OLD_ADDR}/utxo`)
      return okRes(rawTxs.map(({ txid }) => ({ txid, vout: 0, value: 1 })));
    const match = /^\/tx\/([0-9a-f]{64})\/hex$/.exec(path);
    if (match && byTxid.has(match[1])) {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight--;
      return okRes(byTxid.get(match[1])!);
    }
    return errRes(404, 'Not Found');
  };
  const unspent = await new EsploraProvider(fetch, NODE_URL).unspent(OLD_ADDR, { concurrency: 2 });
  deepStrictEqual(unspent.balance, 10n);
  deepStrictEqual(maxInFlight <= 2, true);
});

it('EsploraProvider: unspent stops raw-tx fan-out after a failure', async () => {
  const rawTxs = Array.from({ length: 10 }, (_, i) => fakeRawTx(i));
  let started = 0;
  const fetch = async (url: string): Promise<MockRes> => {
    const path = url.slice(NODE_URL.length);
    if (path === `/address/${OLD_ADDR}/utxo`)
      return okRes(rawTxs.map(({ txid }) => ({ txid, vout: 0, value: 1 })));
    started++;
    if (path === `/tx/${rawTxs[0].txid}/hex`) {
      await new Promise((resolve) => setTimeout(resolve, 5));
      return errRes(400, 'Bad Request');
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    const found = rawTxs.find(({ txid }) => path === `/tx/${txid}/hex`);
    return found ? okRes(found.raw) : errRes(404, 'Not Found');
  };
  await rejects(() => new EsploraProvider(fetch, NODE_URL).unspent(OLD_ADDR, { concurrency: 2 }));
  // Workers finish their in-flight item but must not pull new ones after the
  // first failure: 2 started (one per worker), not all 10.
  deepStrictEqual(started <= 3, true);
});

it('EsploraProvider: history streams newest-first and stops fetching early', async () => {
  const rawTxs = Array.from({ length: 50 }, (_, i) => fakeRawTx(i));
  const txids = rawTxs.map((i) => i.txid);
  const routes: Record<string, unknown> = Object.fromEntries(
    rawTxs.map(({ txid, raw }) => [`/tx/${txid}/hex`, raw])
  );
  routes[`/address/${OLD_ADDR}/txs`] = txids.slice(0, 25).map(fakeConfirmedTx);
  routes[`/address/${OLD_ADDR}/txs/chain/${txids[24]}`] = txids.slice(25).map(fakeConfirmedTx);
  routes[`/address/${OLD_ADDR}/txs/chain/${txids[49]}`] = [];
  const net = new EsploraProvider(routed(routes), NODE_URL);
  const rows = await collect(net.history(OLD_ADDR));
  deepStrictEqual(
    rows.map((tx) => tx.txid),
    txids
  );
  deepStrictEqual(rows, (await net.transfers(OLD_ADDR)).reverse());
  // Early stop: one consumed row costs the first page and its raw txs, and
  // never touches the second pagination page.
  const calls: string[] = [];
  const early = new EsploraProvider(routed(routes, calls), NODE_URL);
  for await (const tx of early.history(OLD_ADDR)) {
    deepStrictEqual(tx.txid, txids[0]);
    break;
  }
  deepStrictEqual(calls.filter((call) => call.includes('/txs/chain/')).length, 0);
  deepStrictEqual(calls.filter((call) => call.includes('/hex')).length, 25);
});

it('EsploraProvider: history reports exact scan progress', async () => {
  const rawTxs = Array.from({ length: 50 }, (_, i) => fakeRawTx(i));
  const txids = rawTxs.map((i) => i.txid);
  const routes: Record<string, unknown> = Object.fromEntries(
    rawTxs.map(({ txid, raw }) => [`/tx/${txid}/hex`, raw])
  );
  routes[`/address/${OLD_ADDR}/txs`] = txids.slice(0, 25).map(fakeConfirmedTx);
  routes[`/address/${OLD_ADDR}/txs/chain/${txids[24]}`] = txids.slice(25).map(fakeConfirmedTx);
  routes[`/address/${OLD_ADDR}/txs/chain/${txids[49]}`] = [];
  routes[`/address/${OLD_ADDR}`] = {
    chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 50 },
    mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
  };
  const events: ScanProgress[] = [];
  const net = new EsploraProvider(routed(routes), NODE_URL);
  await collect(net.history(OLD_ADDR, { onProgress: (progress) => events.push(progress) }));
  deepStrictEqual(events.length, 50);
  deepStrictEqual(events[0], { scannedTxs: 1, totalTxs: 50, percent: 2, currentBlock: 700_000 });
  deepStrictEqual(events[49], {
    scannedTxs: 50,
    totalTxs: 50,
    percent: 100,
    currentBlock: 700_000,
  });
});

it('EsploraProvider: scans abort via AbortSignal', async () => {
  const controller = new AbortController();
  const reason = new Error('stop scan');
  controller.abort(reason);
  let calls = 0;
  const net = new EsploraProvider(async () => {
    calls++;
    return okRes([]);
  }, NODE_URL);
  await rejects(() => net.transfers(OLD_ADDR, { signal: controller.signal }), reason);
  const stream = net.history(OLD_ADDR, { signal: controller.signal });
  await rejects(() => stream.next(), reason);
  await rejects(() => net.unspent(OLD_ADDR, { signal: controller.signal }), reason);
  deepStrictEqual(calls, 0);
});

it('EsploraProvider: history observes aborts between buffered rows', async () => {
  const txs = [fakeRawTx(0), fakeRawTx(1)];
  const routes = Object.fromEntries(txs.map((tx) => [`/tx/${tx.txid}/hex`, tx.raw]));
  routes[`/address/${OLD_ADDR}/txs`] = txs.map((tx) => fakeConfirmedTx(tx.txid));
  const controller = new AbortController();
  const reason = new Error('stop buffered history');
  const stream = new EsploraProvider(routed(routes), NODE_URL).history(OLD_ADDR, {
    signal: controller.signal,
  });
  await stream.next();
  // Both raws are resolved; cancellation must still win before the second yield.
  controller.abort(reason);
  await rejects(() => stream.next(), reason);
});

it('EsploraProvider: historyMulti merges watched addresses into one stream', async () => {
  const mk = (outputs: { address: string; value: bigint }[], index: number) => {
    const tx = new Transaction({ disableScriptCheck: true });
    for (const { address, value } of outputs) tx.addOutputAddress(address, value);
    tx.addInput({ txid: new Uint8Array(32), index, finalScriptSig: Uint8Array.of(index) });
    return tx;
  };
  const txA = mk([{ address: OLD_ADDR, value: 1n }], 0);
  const txB = mk([{ address: TAPROOT_ADDR, value: 2n }], 1);
  const txAB = mk(
    [
      { address: OLD_ADDR, value: 3n },
      { address: TAPROOT_ADDR, value: 4n },
    ],
    2
  );
  const meta = (tx: Transaction, block: number, outputs: { address: string; value: number }[]) => ({
    txid: tx.id,
    version: 2,
    locktime: 0,
    vin: [],
    vout: outputs.map(({ address, value }) => ({
      scriptpubkey: '00',
      scriptpubkey_address: address,
      value,
    })),
    size: 100,
    weight: 400,
    fee: 10,
    status: {
      confirmed: true,
      block_height: block,
      block_hash: '0'.repeat(64),
      block_time: 1_700_000_000,
    },
  });
  const sharedOuts = [
    { address: OLD_ADDR, value: 3 },
    { address: TAPROOT_ADDR, value: 4 },
  ];
  const routes = {
    [`/address/${OLD_ADDR}/txs`]: [
      meta(txAB, 150, sharedOuts),
      meta(txA, 100, [{ address: OLD_ADDR, value: 1 }]),
    ],
    [`/address/${TAPROOT_ADDR}/txs`]: [
      meta(txB, 200, [{ address: TAPROOT_ADDR, value: 2 }]),
      meta(txAB, 150, sharedOuts),
    ],
    [`/tx/${txA.id}/hex`]: txA.hex,
    [`/tx/${txB.id}/hex`]: txB.hex,
    [`/tx/${txAB.id}/hex`]: txAB.hex,
  };
  const calls: string[] = [];
  const net = new EsploraProvider(routed(routes, calls), NODE_URL);
  const newest = await collect(net.historyMulti([OLD_ADDR, TAPROOT_ADDR]));
  // The shared tx is discovered by both address streams but fetched once.
  deepStrictEqual(calls.filter((call) => call === `GET /tx/${txAB.id}/hex`).length, 1);
  deepStrictEqual(
    newest.map((tx) => ({ txid: tx.txid, addresses: tx.addresses })),
    [
      { txid: txB.id, addresses: [TAPROOT_ADDR] },
      { txid: txAB.id, addresses: [OLD_ADDR, TAPROOT_ADDR] },
      { txid: txA.id, addresses: [OLD_ADDR] },
    ]
  );
  const oldest = await collect(net.historyMulti([OLD_ADDR, TAPROOT_ADDR], { order: 'oldest' }));
  deepStrictEqual(
    oldest.map((tx) => tx.txid),
    [txA.id, txAB.id, txB.id]
  );
  throws(
    () => net.historyMulti([]),
    new EsploraError('"addresses" expected non-empty array, got type=object')
  );
  // A chain cursor exists in at most one address's history; fanning it out
  // would silently drop the other addresses' rows.
  throws(
    () => net.historyMulti([OLD_ADDR, TAPROOT_ADDR], { afterTxid: txA.id }),
    new EsploraError('expected historyMulti without afterTxid')
  );
  // Participant matching uses the backend's canonical encoding, so valid but
  // non-canonical inputs (uppercase bech32) must still be tagged.
  const upper = await collect(net.historyMulti([OLD_ADDR.toUpperCase()]));
  deepStrictEqual(
    upper.map((tx) => ({ txid: tx.txid, addresses: tx.addresses })),
    [
      { txid: txAB.id, addresses: [OLD_ADDR] },
      { txid: txA.id, addresses: [OLD_ADDR] },
    ]
  );
});

it('EsploraProvider: historyMulti yields a resolved head before advancing its stream', async () => {
  const txs = Array.from({ length: 25 }, (_, i) => fakeRawTx(i));
  const routes = Object.fromEntries(txs.map((tx) => [`/tx/${tx.txid}/hex`, tx.raw]));
  routes[`/address/${OLD_ADDR}/txs`] = txs.map((tx) => fakeConfirmedTx(tx.txid));
  const nextPath = `/address/${OLD_ADDR}/txs/chain/${txs[24].txid}`;
  const failure = new EsploraError(`GET ${nextPath} failed 404 Not Found`, {
    status: 404,
    path: nextPath,
  });
  const scan = async (multi: boolean) => {
    const net = new EsploraProvider(routed(routes), NODE_URL);
    const stream = multi ? net.historyMulti([OLD_ADDR]) : net.history(OLD_ADDR);
    const rows: string[] = [];
    await rejects(async () => {
      for await (const row of stream) rows.push(row.txid);
    }, failure);
    return rows;
  };
  // One full page makes both public APIs fail on the same following-page request.
  const history = await scan(false);
  deepStrictEqual(
    history,
    txs.map((tx) => tx.txid)
  );
  deepStrictEqual(await scan(true), history);
});

it('EsploraProvider: waitForTx polls status until confirmed', async () => {
  const confirmed = {
    confirmed: true,
    block_height: 700_000,
    block_hash: '0'.repeat(64),
    block_time: 1_700_000_000,
  };
  let statusCalls = 0;
  const fetch = async (url: string): Promise<MockRes> => {
    const path = url.slice(NODE_URL.length);
    if (path !== `/tx/${TAPROOT_TX}/status`) return errRes(400, 'Bad Request');
    statusCalls++;
    if (statusCalls === 1) return errRes(404, 'Not Found'); // not yet propagated
    if (statusCalls === 2) return okRes({ confirmed: false });
    return okRes(confirmed);
  };
  const net = new EsploraProvider(fetch, NODE_URL);
  deepStrictEqual(await net.waitForTx(TAPROOT_TX, { pollIntervalMs: 1 }), {
    confirmed: true,
    block: 700_000,
    blockHash: '0'.repeat(64),
    timestamp: 1_700_000_000_000,
  });
  deepStrictEqual(statusCalls, 3);
});

it('EsploraProvider: waitForTx polls through transient outages', async () => {
  const confirmed = {
    confirmed: true,
    block_height: 700_000,
    block_hash: '0'.repeat(64),
    block_time: 1_700_000_000,
  };
  // A backend outage between polls must not reject a wait that is documented
  // to run until timeoutMs; the next poll retries.
  let calls = 0;
  const fetch = async (): Promise<MockRes> =>
    ++calls < 3 ? errRes(503, 'Service Unavailable') : okRes(confirmed);
  const status = await new EsploraProvider(fetch, NODE_URL).waitForTx(TAPROOT_TX, {
    pollIntervalMs: 1,
  });
  deepStrictEqual(status.block, 700_000);
  deepStrictEqual(calls, 3);
  // Non-transient failures still reject on the first poll.
  let badCalls = 0;
  const badFetch = async (): Promise<MockRes> => {
    badCalls++;
    return errRes(400, 'Bad Request');
  };
  await rejects(() =>
    new EsploraProvider(badFetch, NODE_URL).waitForTx(TAPROOT_TX, { pollIntervalMs: 1 })
  );
  deepStrictEqual(badCalls, 1);
});

it('EsploraProvider: waitForTx waits for extra confirmations and times out', async () => {
  const confirmed = {
    confirmed: true,
    block_height: 700_000,
    block_hash: '0'.repeat(64),
    block_time: 1_700_000_000,
  };
  let heightCalls = 0;
  const fetch = async (url: string): Promise<MockRes> => {
    const path = url.slice(NODE_URL.length);
    if (path === `/tx/${TAPROOT_TX}/status`) return okRes(confirmed);
    if (path === '/blocks/tip/height') {
      heightCalls++;
      return okRes(heightCalls < 2 ? '700000' : '700002');
    }
    return errRes(400, 'Bad Request');
  };
  const net = new EsploraProvider(fetch, NODE_URL);
  const status = await net.waitForTx(TAPROOT_TX, { confirmations: 3, pollIntervalMs: 1 });
  deepStrictEqual(status.block, 700_000);
  deepStrictEqual(heightCalls, 2);
  const pending = new EsploraProvider(async () => okRes({ confirmed: false }), NODE_URL);
  await rejects(
    () => pending.waitForTx(TAPROOT_TX, { pollIntervalMs: 1, timeoutMs: 5 }),
    new EsploraError('waitForTx: timeout')
  );
  let calls = 0;
  const bounded = new EsploraProvider(async () => {
    calls++;
    return okRes({ confirmed: false });
  }, NODE_URL);
  await rejects(
    () => bounded.waitForTx(TAPROOT_TX, { pollIntervalMs: 80, timeoutMs: 20 }),
    new EsploraError('waitForTx: timeout')
  );
  deepStrictEqual(calls, 1);
  let release!: (res: MockRes) => void;
  let signal: AbortSignal | undefined;
  const stalled = new EsploraProvider((_url, opts) => {
    signal = opts?.signal;
    return new Promise<MockRes>((resolve) => (release = resolve));
  }, NODE_URL);
  const wait = stalled.waitForTx(TAPROOT_TX, { timeoutMs: 10, pollIntervalMs: 1 });
  const settled = wait.then(
    () => 'resolved' as const,
    (error: unknown) => error
  );
  const early = await Promise.race([
    settled,
    new Promise<'still pending'>((resolve) => setTimeout(() => resolve('still pending'), 40)),
  ]);
  // Release a transport that ignores AbortSignal so the test leaves no pending work.
  release(okRes({ confirmed: true, block_height: 1 }));
  await settled;
  deepStrictEqual(early, new EsploraError('waitForTx: timeout'));
  deepStrictEqual(signal?.aborted, true);
});

// Regression tests.
const TXID_01 = '00'.repeat(31) + '01';
const privA = hex.decode('02'.repeat(32));

// Stub Esplora transport: routes map path -> response body.
const mkFetch =
  (routes: Record<string, { json?: unknown; text?: string }>) => async (url: string) => {
    const r = routes[url.replace('http://e', '')];
    return {
      ok: !!r,
      status: r ? 200 : 404,
      json: async () => r?.json,
      text: async () => r?.text ?? 'not found',
    };
  };
// Consensus-valid tx with a version outside the standard [-1, 0, 1, 2, 3] set.
const weirdVersionTx = () => {
  const spend = p2wpkh(pubECDSA(privA));
  const raw = RawTx.encode({
    version: 305419896, // 0x12345678
    segwitFlag: false,
    inputs: [
      {
        txid: hex.decode(TXID_01),
        index: 0,
        finalScriptSig: new Uint8Array(0),
        sequence: 4294967295,
      },
    ],
    outputs: [{ amount: 1000n, script: spend.script }],
    lockTime: 0,
  } as any);
  return { spend, raw, txid: hex.encode(sha256x2(raw).reverse()) };
};

it('Esplora txInfo parses non-standard tx versions', async () => {
  // Fixed issue: parseRawTx did not pass allowUnknownVersion, so txInfo/transfers
  // failed on consensus-valid history with versions outside [-1, 0, 1, 2, 3].
  const { spend, raw, txid } = weirdVersionTx();
  const net = new EsploraProvider(
    mkFetch({
      [`/tx/${txid}`]: {
        json: {
          txid,
          version: 305419896,
          locktime: 0,
          size: raw.length,
          weight: raw.length * 4,
          fee: 0,
          vin: [{ txid: TXID_01, vout: 0 }],
          vout: [{ scriptpubkey: hex.encode(spend.script), value: 1000 }],
          status: { confirmed: false },
        },
      },
      [`/tx/${txid}/hex`]: { text: hex.encode(raw) },
    }) as any,
    'http://e'
  );
  const info = await net.txInfo(txid);
  deepStrictEqual(info.version, 305419896);
  deepStrictEqual(info.raw, hex.encode(raw));
});

it('Esplora unspent() verifies fetched prev-tx hex', async () => {
  // Fixed issue: unlike txInfo/transfers, unspent() never checked that the raw hex
  // served for /tx/:txid/hex is actually that transaction, so balance and
  // nonWitnessUtxo came from whatever the backend chose to return.
  const { spend, raw, txid } = weirdVersionTx();
  const addr = spend.address!;
  const wrongTxid = '11'.repeat(32); // served raw hashes to `txid`, not this
  await rejects(
    () =>
      new EsploraProvider(
        mkFetch({
          [`/address/${addr}/utxo`]: { json: [{ txid: wrongTxid, vout: 0 }] },
          [`/tx/${wrongTxid}/hex`]: { text: hex.encode(raw) },
        }) as any,
        'http://e'
      ).unspent(addr),
    /wrong raw txid/
  );
  const ok = await new EsploraProvider(
    mkFetch({
      [`/address/${addr}/utxo`]: { json: [{ txid, vout: 0 }] },
      [`/tx/${txid}/hex`]: { text: hex.encode(raw) },
    }) as any,
    'http://e'
  ).unspent(addr);
  deepStrictEqual(ok.balance, 1000n);
  deepStrictEqual(ok.utxo.length, 1);
});

it('Esplora transfers() detects pagination cursor loops', async () => {
  // Hardening: a backend that ignores the /txs/chain/:txid cursor and returns the
  // same full page forever used to make transfers() loop until out of memory.
  const addr = p2wpkh(pubECDSA(privA)).address!;
  const page = Array.from({ length: 25 }, (_, i) => ({
    txid: i.toString(16).padStart(64, '0'),
    version: 2,
    locktime: 0,
    size: 100,
    weight: 400,
    fee: 0,
    vin: [],
    vout: [],
    status: { confirmed: true, block_height: 10, block_hash: '22'.repeat(32), block_time: 1 },
  }));
  const sameForever = async () => ({
    ok: true,
    status: 200,
    json: async () => page,
    text: async () => '',
  });
  await rejects(
    () => new EsploraProvider(sameForever as any, 'http://e').transfers(addr),
    /pagination cursor loop/
  );
});

it.runWhen(import.meta.url);

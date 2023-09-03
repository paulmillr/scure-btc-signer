# scure-btc-signer

Audited & minimal library for creating, signing & decoding Bitcoin transactions.

- 🔒 [**Audited**](#security) by an independent security firm
- ✍️ Create transactions, inputs, outputs, sign them
- 📡 No network code: simplified audits and offline usage
- 🎻 Classic & SegWit: P2PK, P2PKH, P2WPKH, P2SH, P2WSH, P2MS
- 🧪 Schnorr & Taproot BIP340/BIP341: P2TR, P2TR-NS, P2TR-MS
- 📨 BIP174 PSBT
- 👥 Multisig support
- 🪶 ~2600 lines

Initial development has been funded by [Ryan Shea](https://shea.io). Check out [the demo](https://signerdemo.micro-btc.dev/) & [its github](https://github.com/shea256/micro-btc-web-demo).

### This library belongs to _scure_

> **scure** — secure, independently audited packages for every use case.

- Minimal or zero dependencies
- Releases are signed with PGP keys and built transparently with NPM provenance
- Check out all libraries:
  [base](https://github.com/paulmillr/scure-base),
  [bip32](https://github.com/paulmillr/scure-bip32),
  [bip39](https://github.com/paulmillr/scure-bip39),
  [btc-signer](https://github.com/paulmillr/scure-btc-signer),
  [starknet](https://github.com/paulmillr/scure-starknet)

## Usage

> npm install @scure/btc-signer

We support all major platforms and runtimes.
For [Deno](https://deno.land), ensure to use [npm specifier](https://deno.land/manual@v1.28.0/node/npm_specifiers).
For React Native, you may need a [polyfill for crypto.getRandomValues](https://github.com/LinusU/react-native-get-random-values).

```ts
import * as btc from '@scure/btc-signer';
// import * as btc from "npm:@scure/btc-signer@1.0.0"; // Deno
```

### Table of Contents

- [Payments](#payments)
  - [P2PK Pay To Public Key](#p2pk-pay-to-public-key)
  - [P2PKH Public Key Hash](#p2pkh-public-key-hash)
  - [P2WPKH Witness Public Key Hash](#p2wpkh-witness-public-key-hash)
  - [P2SH Script Hash](#p2sh-script-hash)
  - [P2WSH Witness Script Hash](#p2wsh-witness-script-hash)
  - [P2SH-P2WSH](#p2sh-p2wsh)
  - [P2MS classic multisig](#p2ms-classic-multisig)
  - [P2TR Taproot](#p2tr-taproot)
  - [P2TR-NS Taproot multisig](#p2tr-ns-taproot-multisig)
  - [P2TR-MS Taproot M-of-N multisig](#p2tr-ms-taproot-m-of-n-multisig)
- [Transaction](#transaction)
  - [Encode/decode](#encodedecode)
  - [Inputs](#inputs)
  - [Outputs](#outputs)
  - [Basic transaction sign](#basic-transaction-sign)
  - [BIP174 PSBT multi-sig example](#bip174-psbt-multi-sig-example)
- [Utils](#utils)
  - [getAddress](#getaddress)
    - [WIF](#wif)
  - [Script](#script)
  - [OutScript](#outscript)

## Payments

BTC has several UTXO types:

- P2PK: Legacy, from 2010
- P2PKH, P2SH, P2MS: Classic
- P2WPKH, P2WSH: classic, SegWit
- P2TR: Taproot, recommended

For test examples, the usage is as following:

```sh
npm install @scure/btc-signer @scure/base assert
```

```ts
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { deepStrictEqual, throws } from 'assert';
```

### P2PK (Pay To Public Key)

Legacy script, doesn't have an address. Must be wrapped in P2SH / P2WSH / P2SH-P2WSH. Not recommended.

```ts
const uncompressed = hex.decode(
  '04ad90e5b6bc86b3ec7fac2c5fbda7423fc8ef0d58df594c773fa05e2c281b2bfe877677c668bd13603944e34f4818ee03cadd81a88542b8b4d5431264180e2c28'
);

deepStrictEqual(btc.p2pk(uncompressed), {
  type: 'pk',
  script: hex.decode(
    '4104ad90e5b6bc86b3ec7fac2c5fbda7423fc8ef0d58df594c773fa05e2c281b2bfe877677c668bd13603944e34f4818ee03cadd81a88542b8b4d5431264180e2c28ac'
  ),
});
```

### P2PKH (Public Key Hash)

Classic (pre-SegWit) address.

```ts
const PubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
deepStrictEqual(btc.p2pkh(PubKey), {
  type: 'pkh',
  address: '134D6gYy8DsR5m4416BnmgASuMBqKvogQh',
  script: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
// P2SH-P2PKH
deepStrictEqual(btc.p2sh(btc.p2pkh(PubKey)), {
  type: 'sh',
  address: '3EPhLJ1FuR2noj6qrTs4YvepCvB6sbShoV',
  script: hex.decode('a9148b530b962725af3bb7c818f197c619db3f71495087'),
  redeemScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
// P2WSH-P2PKH
deepStrictEqual(btc.p2wsh(btc.p2pkh(PubKey)), {
  type: 'wsh',
  address: 'bc1qhxtthndg70cthfasy8y4qlk9h7r3006azn9md0fad5dg9hh76nkqaufnuz',
  script: hex.decode('0020b996bbcda8f3f0bba7b021c9507ec5bf8717bf5d14cbb6bd3d6d1a82defed4ec'),
  witnessScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
// P2SH-P2WSH-P2PKH
deepStrictEqual(btc.p2sh(btc.p2wsh(btc.p2pkh(PubKey))), {
  type: 'sh',
  address: '3EHxWHyLv5Seu5Cd6D1cH56jLKxSi3ps8C',
  script: hex.decode('a9148a3d36fb710a9c7cae06cfcdf39792ff5773e8f187'),
  redeemScript: hex.decode('0020b996bbcda8f3f0bba7b021c9507ec5bf8717bf5d14cbb6bd3d6d1a82defed4ec'),
  witnessScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
```

### P2WPKH (Witness Public Key Hash)

SegWit V0 version of [P2PKH](#p2pkh-public-key-hash). Basic bech32 address. Can't be wrapped in [P2WSH](#p2wsh-witness-script-hash).

```ts
const PubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
deepStrictEqual(btc.p2wpkh(PubKey), {
  type: 'wpkh',
  address: 'bc1qz69ej270c3q9qvgt822t6pm3zdksk2x35j2jlm',
  script: hex.decode('0014168b992bcfc44050310b3a94bd0771136d0b28d1'),
});
// P2SH-P2WPKH
deepStrictEqual(btc.p2sh(btc.p2wpkh(PubKey)), {
  type: 'sh',
  address: '3BCuRViGCTXmQjyJ9zjeRUYrdZTUa38zjC',
  script: hex.decode('a91468602f2db7b7d7cdcd2639ab6bf7f5bfe828e53f87'),
  redeemScript: hex.decode('0014168b992bcfc44050310b3a94bd0771136d0b28d1'),
});
```

### P2SH (Script Hash)

Classic (pre-SegWit) script address. Useful for multisig and other advanced use-cases. Consumes full output of other payments — NOT only script.

Required tx input fields to make it spendable: `redeemScript`

```ts
const PubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
// Wrap P2PKH in P2SH
deepStrictEqual(btc.p2sh(btc.p2pkh(PubKey)), {
  type: 'sh',
  address: '3EPhLJ1FuR2noj6qrTs4YvepCvB6sbShoV',
  script: hex.decode('a9148b530b962725af3bb7c818f197c619db3f71495087'),
  redeemScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
```

### P2WSH (Witness Script Hash)

SegWit V0 version of [P2SH](#p2sh-script-hash).

Required tx input fields to make it spendable: `witnessScript`

```ts
const PubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
deepStrictEqual(btc.p2wsh(btc.p2pkh(PubKey)), {
  type: 'wsh',
  address: 'bc1qhxtthndg70cthfasy8y4qlk9h7r3006azn9md0fad5dg9hh76nkqaufnuz',
  script: hex.decode('0020b996bbcda8f3f0bba7b021c9507ec5bf8717bf5d14cbb6bd3d6d1a82defed4ec'),
  witnessScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
```

### P2SH-P2WSH

Not really script type, but construction of P2WSH inside P2SH.

Required tx input fields to make it spendable: `redeemScript`, `witnessScript`

```ts
const PubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
deepStrictEqual(btc.p2sh(btc.p2wsh(btc.p2pkh(PubKey))), {
  type: 'sh',
  address: '3EHxWHyLv5Seu5Cd6D1cH56jLKxSi3ps8C',
  script: hex.decode('a9148a3d36fb710a9c7cae06cfcdf39792ff5773e8f187'),
  redeemScript: hex.decode('0020b996bbcda8f3f0bba7b021c9507ec5bf8717bf5d14cbb6bd3d6d1a82defed4ec'),
  witnessScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
});
```

### P2MS (classic multisig)

Classic / segwit (pre-taproot) M-of-N Multisig. Doesn't have an address, must be wrapped in P2SH / P2WSH / P2SH-P2WSH.

Duplicate public keys are not accepted to reduce mistakes. Use flag `allowSamePubkeys` to override the behavior, for cases like `2-of-[A,A,B,C]`, which can be signed by `A or (B and C)`.

```ts
const PubKeys = [
  hex.decode('030000000000000000000000000000000000000000000000000000000000000001'),
  hex.decode('030000000000000000000000000000000000000000000000000000000000000002'),
  hex.decode('030000000000000000000000000000000000000000000000000000000000000003'),
];
// Multisig 2-of-3 wrapped in P2SH
deepStrictEqual(btc.p2sh(btc.p2ms(2, PubKeys)), {
  type: 'sh',
  address: '3G4AeQtzCLoDAyv2eb3UVTG5atfkyHtuRn',
  script: hex.decode('a9149d91c6de4eacde72a7cc86bff98d1915b3c7818f87'),
  redeemScript: hex.decode(
    '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
  ),
});
// Multisig 2-of-3 wrapped in P2WSH
deepStrictEqual(btc.p2wsh(btc.p2ms(2, PubKeys)), {
  type: 'wsh',
  address: 'bc1qwnhzkn8wcyyrnfyfcp7555urssu5dq0rmnvg70hg02z3nxgg4f0qljmr2h',
  script: hex.decode('002074ee2b4ceec10839a489c07d4a538384394681e3dcd88f3ee87a85199908aa5e'),
  witnessScript: hex.decode(
    '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
  ),
});
// Multisig 2-of-3 wrapped in P2SH-P2WSH
deepStrictEqual(btc.p2sh(btc.p2wsh(btc.p2ms(2, PubKeys))), {
  type: 'sh',
  address: '3HKWSo57kmcJZ3h43pXS3m5UESR4wXcWTd',
  script: hex.decode('a914ab70ab84b12b891364b4b2a14ca813cac308b24287'),
  redeemScript: hex.decode('002074ee2b4ceec10839a489c07d4a538384394681e3dcd88f3ee87a85199908aa5e'),
  witnessScript: hex.decode(
    '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
  ),
});
// Useful util: wraps P2MS in P2SH or P2WSH
deepStrictEqual(btc.p2sh(btc.p2ms(2, PubKeys)), btc.multisig(2, PubKeys));
deepStrictEqual(btc.p2wsh(btc.p2ms(2, PubKeys)), btc.multisig(2, PubKeys, undefined, true));
// Sorted multisig (BIP67)
deepStrictEqual(btc.p2sh(btc.p2ms(2, PubKeys)), btc.sortedMultisig(2, PubKeys));
deepStrictEqual(btc.p2wsh(btc.p2ms(2, PubKeys)), btc.sortedMultisig(2, PubKeys, true));
```

### P2TR (Taproot)

TapRoot (SegWit V1) script which replaces both public key and script types from previous versions.

Consumes `p2tr(PubKey?, ScriptTree?)` and works as `PubKey` OR `ScriptTree`, which means
if you use any spendable PubKey and ScriptTree of multi-sig, owner of private key for PubKey will
be able to spend output. If PubKey is undefined we use static unspendable PubKey by default, which leaks information about script type. However, any dynamic unspendable keys will require complex interaction
to sign multi-sig wallets, and there is no BIP/PSBT fields for that yet.

Required tx input fields to make it spendable: `tapInternalKey`, `tapMerkleRoot`, `tapLeafScript`

```ts
const PubKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
// Key Path Spend (owned of private key for PubKey can spend)
deepStrictEqual(btc.p2tr(PubKey), {
  type: 'tr',
  address: 'bc1p7yu5dsly83jg5tkxcljsa30vnpdpl22wr6rty98t6x6p6ekz2gkqzf2t2s',
  script: hex.decode('5120f13946c3e43c648a2ec6c7e50ec5ec985a1fa94e1e86b214ebd1b41d66c2522c'),
  tweakedPubkey: hex.decode('f13946c3e43c648a2ec6c7e50ec5ec985a1fa94e1e86b214ebd1b41d66c2522c'),
  tapInternalKey: hex.decode('0101010101010101010101010101010101010101010101010101010101010101'),
});

const clean = (x) => ({ type: x.type, address: x.address, script: hex.encode(x.script) });

const PubKey2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
const PubKey3 = hex.decode('1212121212121212121212121212121212121212121212121212121212121212');
// Nested P2TR, owner of private key for any of PubKeys can spend whole
// By default P2TR expects binary tree, but btc.p2tr can build it if list of scripts passed.
// Also, you can include {weight: N} to scripts to create differently balanced tree.
deepStrictEqual(
  clean(btc.p2tr(undefined, [btc.p2tr_pk(PubKey), btc.p2tr_pk(PubKey2), btc.p2tr_pk(PubKey3)])),
  {
    type: 'tr',
    // weights for bitcoinjs-lib: [3,2,1]
    address: 'bc1pj2uvajyygyu2zw0rg0d6yxdsc920kzc5pamfgtlqepe30za922cqjjmkta',
    script: '512092b8cec8844138a139e343dba219b0c154fb0b140f76942fe0c873178ba552b0',
  }
);
// If scriptsTree is already binary tree, it will be used as-is
deepStrictEqual(
  clean(btc.p2tr(undefined, [btc.p2tr_pk(PubKey2), [btc.p2tr_pk(PubKey), btc.p2tr_pk(PubKey3)]])),
  {
    type: 'tr',
    // default weights for bitcoinjs-lib
    address: 'bc1pvue6sk9efyvcvpzzqkg8at4qy2u67zj7rj5sfsy573m7alxavqjqucc26a',
    script: '51206733a858b9491986044205907eaea022b9af0a5e1ca904c094f477eefcdd6024',
  }
);
```

### P2TR-NS (Taproot multisig)

Taproot N-of-N multisig (`[<PubKeys[0:n-1]> CHECKSIGVERIFY] <PubKeys[n-1]> CHECKSIG`).

First arg is M, if M!=PubKeys.length, it will create a multi-leaf M-of-N taproot script tree.
This allows one to reveal only `M` PubKeys on spend, without any information about the others.
This is fast for cases like 15-of-20, but extremely slow for cases like 5-of-20.

Duplicate public keys are not accepted to reduce mistakes. Use flag `allowSamePubkeys` to override the behavior, for cases like `2-of-[A,A,B,C]`, which can be signed by `A or (B and C)`.

```ts
const PubKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
const PubKey2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
const PubKey3 = hex.decode('1212121212121212121212121212121212121212121212121212121212121212');

// Simple 3-of-3 multisig
// Creates a single script that requires all three pubkeys: [PubKey, PubKey2, PubKey3]
deepStrictEqual(btc.p2tr_ns(3, [PubKey, PubKey2, PubKey3]), [
  {
    type: 'tr_ns',
    script: hex.decode(
      '200101010101010101010101010101010101010101010101010101010101010101ad200202020202020202020202020202020202020202020202020202020202020202ad201212121212121212121212121212121212121212121212121212121212121212ac'
    ),
  },
]);
// Simple 2-of-3 multisig
// If M (pubkeys required) is less than N (# of pubkeys), then multiple scripts are created: [[PubKey, PubKey2], [PubKey, PubKey3], [PubKey2, PubKey3]]
const clean = (x) => ({ type: x.type, address: x.address, script: hex.encode(x.script) });
deepStrictEqual(clean(btc.p2tr(undefined, btc.p2tr_ns(2, [PubKey, PubKey2, PubKey3]))), {
  type: 'tr',
  address: 'bc1pevfcmnkqqq09a4n0fs8c7mwlc6r4efqpvgyqpjvegllavgw235fq3kz7a0',
  script: '5120cb138dcec0001e5ed66f4c0f8f6ddfc6875ca401620800c99947ffd621ca8d12',
});
```

### P2TR-MS (Taproot M-of-N multisig)

M-of-N single leaf TapRoot multisig (`<PubKeys[0]> CHECKSIG [<PubKeys[1:n]> CHECKSIGADD] <M> NUMEQUAL`)

Duplicate public keys are not accepted to reduce mistakes. Use flag `allowSamePubkeys` to override the behavior, for cases like `2-of-[A,A,B,C]`, which can be signed by `A or (B and C)`.

**Experimental**, use at your own risk.

```ts
const PubKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
const PubKey2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
const PubKey3 = hex.decode('1212121212121212121212121212121212121212121212121212121212121212');
// 2-of-3 TapRoot multisig
deepStrictEqual(btc.p2tr_ms(2, [PubKey, PubKey2, PubKey3]), {
  type: 'tr_ms',
  script: hex.decode(
    '200101010101010101010101010101010101010101010101010101010101010101ac200202020202020202020202020202020202020202020202020202020202020202ba201212121212121212121212121212121212121212121212121212121212121212ba529c'
  ),
});
// Creates a single script for [PubKey, PubKey2, PubKey3]
const clean = (x) => ({ type: x.type, address: x.address, script: hex.encode(x.script) });
deepStrictEqual(clean(btc.p2tr(undefined, btc.p2tr_ms(2, [PubKey, PubKey2, PubKey3]))), {
  type: 'tr',
  address: 'bc1p6m2xevckax9zucumnnyvu4xhxem66ugc5r2zlw2a20s0hxnutl8qfef23s',
  script: '5120d6d46cb316e98a2e639b9cc8ce54d73677ad7118a0d42fb95d53e0fb9a7c5fce',
});
```

### P2TR-PK (Taproot single P2PK script)

Specific case of `p2tr_ns(1, [pubkey])`, which is the same as the BTC descriptor: `tr($H,pk(PUBKEY))`

```ts
const PubKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
// P2PK for taproot
const clean = (x) => ({ type: x.type, address: x.address, script: hex.encode(x.script) });
deepStrictEqual(clean(btc.p2tr(undefined, [btc.p2tr_pk(PubKey)])), {
  type: 'tr',
  address: 'bc1pfj6w68w3v2f4pkzesc9tsqfvy5znw5qgydwa832v3v83vjn76kdsmr4360',
  script: '51204cb4ed1dd1629350d859860ab8012c2505375008235dd3c54c8b0f164a7ed59b',
});
```

## Transaction

### Encode/decode

We support both PSBTv0 and draft PSBTv2 (there is no PSBTv1). If PSBTv2 transaction is encoded into PSBTv1, all PSBTv2 fields will be stripped.

We strip 'unknown' keys inside PSBT, they needed for new version/features support,
however any unsupported feature/new version can significantly break assumptions about code.
If you have use-case where they are needed, create a github issue.

PSBTv2 features tx_modifiable and taproot+bip32 are not supported yet.

```ts
// Decode
Transaction.fromRaw(raw: Bytes, opts: TxOpts = {}); // Raw tx
Transaction.fromPSBT(psbt: Bytes, opts: TxOpts = {}); // PSBT tx
// Encode
tx.unsignedTx; // Bytes of raw unsigned tx
tx.hex; // hex encoded signed raw tx
tx.toPSBT(ver = this.PSBTVersion); // PSBT
```

### Inputs

We have txid (BE) instead of hash (LE) in transactions. We can support both,
but txid is consistent across block explorers, while some explorers treat hash
as txid - so hash is not consistent.

Use `getInput` and `inputsLength` to read information about inputs: they return a copy.
This is neccessary to avoid accidential modification of internal structures without calling methods (addInput/updateInput) that will verify correctness.

```ts
type TransactionInput = {
  txid?: Bytes,
  index?: number,
  nonWitnessUtxo?: <RawTransactionBytesOrHex>,
  witnessUtxo?: {script?: Bytes; amount: bigint},
  partialSig?: [Bytes, Bytes][]; // [PubKey, Signature]
  sighashType?: P.U32LE,
  redeemScript?: Bytes,
  witnessScript?: Bytes,
  bip32Derivation?: [Bytes, {fingerprint: number; path: number[]}]; // [PubKey, DeriviationPath]
  finalScriptSig?: Bytes,
  finalScriptWitness?: Bytes[],
  porCommitment?: Bytes,
  sequence?: number,
  requiredTimeLocktime?: number,
  requiredHeightLocktime?: number,
  tapKeySig?: Bytes,
  tapScriptSig?: [Bytes, Bytes][]; // [PubKeySchnorr, LeafHash]
  // [ControlBlock, ScriptWithVersion]
  tapLeafScript?: [{version: number; internalKey: Bytes; merklePath: Bytes[]}, Bytes];
  tapInternalKey?: Bytes,
  tapMerkleRoot?: Bytes,
};

tx.addInput(input: TransactionInput): number;
tx.updateInput(idx: number, input: TransactionInput);

// Input
tx.addInput({ txid: new Uint8Array(32), index: 0 });
deepStrictEqual(tx.inputs[0], {
  txid: new Uint8Array(32),
  index: 0,
  sequence: btc.DEFAULT_SEQUENCE,
});
// Update basic value
tx.updateInput(0, { index: 10 });
deepStrictEqual(tx.inputs[0], {
  txid: new Uint8Array(32),
  index: 10,
  sequence: btc.DEFAULT_SEQUENCE,
});
// Add value as hex
tx.addInput({
  txid: '0000000000000000000000000000000000000000000000000000000000000000',
  index: 0,
});
deepStrictEqual(tx.inputs[2], {
  txid: new Uint8Array(32),
  index: 0,
  sequence: btc.DEFAULT_SEQUENCE,
});
// Update key map
const pubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
const bip1 = [pubKey, { fingerprint: 5, path: [1, 2, 3] }];
const pubKey2 = hex.decode('030000000000000000000000000000000000000000000000000000000000000002');
const bip2 = [pubKey2, { fingerprint: 6, path: [4, 5, 6] }];
const pubKey3 = hex.decode('030000000000000000000000000000000000000000000000000000000000000003');
const bip3 = [pubKey3, { fingerprint: 7, path: [7, 8, 9] }];
// Add K-V
tx.updateInput(0, { bip32Derivation: [bip1] });
deepStrictEqual(tx.inputs[0].bip32Derivation, [bip1]);
// Add another K-V
tx.updateInput(0, { bip32Derivation: [bip2] });
deepStrictEqual(tx.inputs[0].bip32Derivation, [bip1, bip2]);
// Delete K-V
tx.updateInput(0, { bip32Derivation: [[pubKey, undefined]] });
deepStrictEqual(tx.inputs[0].bip32Derivation, [bip2]);
// Second add of same k-v does nothing
tx.updateInput(0, { bip32Derivation: [bip2] });
deepStrictEqual(tx.inputs[0].bip32Derivation, [bip2]);
// Second add of k-v with different value breaks
throws(() => tx.updateInput(0, { bip32Derivation: [[pubKey2, bip1[1]]] }));
tx.updateInput(0, { bip32Derivation: [bip1, bip2, bip3] });
// Preserves order (re-ordered on PSBT encoding)
deepStrictEqual(tx.inputs[0].bip32Derivation, [bip2, bip1, bip3]);
// PSBT encoding re-order k-v
const tx2 = btc.Transaction.fromPSBT(tx.toPSBT());
deepStrictEqual(tx2.inputs[0].bip32Derivation, [bip1, bip2, bip3]);
// Remove field
tx.updateInput(0, { bip32Derivation: undefined });
deepStrictEqual(tx.inputs[0], {
  txid: new Uint8Array(32),
  index: 10,
  sequence: btc.DEFAULT_SEQUENCE,
});

// Read inputs
for (let i = 0; i < tx.inputsLength; i++) {
  console.log('I', tx.getInput(i));
}
```

### Outputs

`addOutputAddress` uses bigint amounts, which mean satoshis - NOT btc. If you need btc representation, use Decimal:

```ts
const amountSatoshi = btc.Decimal.decode('1.5'); // 1.5 btc in satoshi
```

Use `getOutput` and `outputsLength` to read outputs information. This methods returns copy of output, instead of internal representation.
This is neccessary to avoid accidential modification of internal structures without calling methods (addOutput/updateOutput) that will verify correctness.

```ts
type TransactionOutput = {
  script?: Bytes,
  amount?: bigint,
  redeemScript?: Bytes,
  witnessScript?: Bytes,
  bip32Derivation?: [Bytes, {fingerprint: number; path: number[]}]; // [PubKey, DeriviationPath]
  tapInternalKey?: Bytes,
};

tx.addOutput(o: TransactionOutput): number;
tx.updateOutput(idx: number, output: TransactionOutput);
tx.addOutputAddress(address: string, amount: string | bigint, network = NETWORK): number;

const compressed = hex.decode(
  '030000000000000000000000000000000000000000000000000000000000000001'
);
const script = btc.p2pkh(compressed).script;
tx.addOutput({ script, amount: 100n });
deepStrictEqual(tx.outputs[0], {
  script,
  amount: 100n,
});
// Update basic value
tx.updateOutput(0, { amount: 200n });
deepStrictEqual(tx.outputs[0], {
  script,
  amount: 200n,
});
// Add K-V
tx.updateOutput(0, { bip32Derivation: [bip1] });
deepStrictEqual(tx.outputs[0].bip32Derivation, [bip1]);
// Add another K-V
tx.updateOutput(0, { bip32Derivation: [bip2] });
deepStrictEqual(tx.outputs[0].bip32Derivation, [bip1, bip2]);
// Delete K-V
tx.updateOutput(0, { bip32Derivation: [[pubKey, undefined]] });
deepStrictEqual(tx.outputs[0].bip32Derivation, [bip2]);
// Second add of same k-v does nothing
tx.updateOutput(0, { bip32Derivation: [bip2] });
deepStrictEqual(tx.outputs[0].bip32Derivation, [bip2]);
// Second add of k-v with different value breaks
throws(() => tx.updateOutput(0, { bip32Derivation: [[pubKey2, bip1[1]]] }));
tx.updateOutput(0, { bip32Derivation: [bip1, bip2, bip3] });
// Preserves order (re-ordered on PSBT encoding)
deepStrictEqual(tx.outputs[0].bip32Derivation, [bip2, bip1, bip3]);
// PSBT encoding re-order k-v
const tx3 = btc.Transaction.fromPSBT(tx.toPSBT());
deepStrictEqual(tx3.outputs[0].bip32Derivation, [bip1, bip2, bip3]);
// Remove field
tx.updateOutput(0, { bip32Derivation: undefined });
deepStrictEqual(tx.outputs[0], {
  script,
  amount: 200n,
});

// Read outputs
for (let i = 0; i < tx.outputsLength; i++) {
  console.log('O', tx.getOutput(i));
}
```

### Basic transaction sign

```ts
const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
const txP2WPKH = new btc.Transaction();
for (const inp of TX_TEST_INPUTS) {
  txP2WPKH.addInput({
    txid: inp.txid,
    index: inp.index,
    witnessUtxo: {
      amount: inp.amount,
      script: btc.p2wpkh(secp256k1.getPublicKey(privKey, true)).script,
    },
  });
}
for (const [address, amount] of TX_TEST_OUTPUTS) txP2WPKH.addOutputAddress(address, amount);
deepStrictEqual(hex.encode(txP2WPKH.unsignedTx), RAW_TX_HEX);
txP2WPKH.sign(privKey);
txP2WPKH.finalize();
deepStrictEqual(txP2WPKH.id, 'cbb94443b19861df0824914fa654212facc071854e0df6f7388b482a6394526d');
deepStrictEqual(
  txP2WPKH.hex,
  '010000000001033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c00000000000ffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a20000000000ffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa0000000000ffffffff03e8030000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac881300000000000017a914a860f76561c85551594c18eecceffaee8c4822d7876b24000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4202473044022024e7b1a6ae19a95c69c192745db09cc54385a80cc7684570cfbf2da84cbbfa0802205ad55efb2019a1aa6edc03cf243989ea428c4d216699cbae2cfaf3c26ddef5650121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0247304402204415ef16f341e888ca2483b767b47fcf22977b6d673c3f7c6cae2f6b4bc2ac08022055be98747345b02a6f40edcc2f80390dcef4efe57b38c1bb7d16bdbca710abfd0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02473044022069769fb5c97a7dd9401dbd3f6d32a38fe82bc8934c49c7c4cd3b39c6d120080c02202c181604203dc45c10e5290ded103195fae117d7fb0db19cdc411e73a76da6cb0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f00000000'
);
```

### BIP174 PSBT multi-sig example

```ts
const testnet = {
  wif: 0xef,
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
};
// The private keys in the tests below are derived from the following master private key:
const epriv =
  'tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF';
const hdkey = bip32.HDKey.fromExtendedKey(epriv, testnet.bip32);
// const seed = 'cUkG8i1RFfWGWy5ziR11zJ5V4U4W3viSFCfyJmZnvQaUsd1xuF3T';
const tx = new btc.Transaction();
// A creator creating a PSBT for a transaction which creates the following outputs:
tx.addOutput({ script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d', amount: btc.Decimal.decode('1.49990000') });
tx.addOutput({ script: '001400aea9a2e5f0f876a588df5546e8742d1d87008f', amount: btc.Decimal.decode('1.00000000') });
// and spends the following inputs:
tx.addInput({
  txid: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
  index: 0,
});
tx.addInput({
  txid: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
  index: 1,
});
// must create this PSBT:
const psbt1 = tx.toPSBT();
// Given the above PSBT, an updater with only the following:
const tx2 = btc.Transaction.fromPSBT(psbt1);
tx2.updateInput(0, {
  nonWitnessUtxo:
    '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000',
  redeemScript:
    '5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
  bip32Derivation: [
    [
      '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
      { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/0'") },
    ],
    [
      '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7',
      { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/1'") },
    ],
  ],
});
tx2.updateInput(1, {
  // use witness utxo ({script, amount})
  witnessUtxo: btc.RawTx.decode(
    hex.decode(
      '0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000'
    )
  ).outputs[1],
  redeemScript: '00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
  witnessScript:
    '522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae',
  bip32Derivation: [
    [
      '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
      { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/2'") },
    ],
    [
      '023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73',
      { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/3'") },
    ],
  ],
});
tx2.updateOutput(0, {
  bip32Derivation: [
    [
      '03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771',
      { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/4'") },
    ],
  ],
});
tx2.updateOutput(1, {
  bip32Derivation: [
    [
      '027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096',
      { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/5'") },
    ],
  ],
});
// Must create this PSBT:
const psbt2 = tx2.toPSBT();
// An updater which adds SIGHASH_ALL to the above PSBT must create this PSBT:
const tx3 = btc.Transaction.fromPSBT(psbt2);
for (let i = 0; i < tx3.inputs.length; i++)
  tx3.updateInput(i, { sighashType: btc.SigHash.ALL });
const psbt3 = tx3.toPSBT();
/*
  Given the above updated PSBT, a signer that supports SIGHASH_ALL for P2PKH and P2WPKH spends and uses RFC6979 for nonce generation and has the following keys:
  - cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr (m/0'/0'/0')
  - cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d (m/0'/0'/2')
*/
// We don't use HDKey, because it will everything because of bip32 derivation
const tx4 = btc.Transaction.fromPSBT(psbt3);
tx4.sign(btc.WIF(testnet).decode('cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr'));
tx4.sign(btc.WIF(testnet).decode('cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d'));
// must create this PSBT:
const psbt4 = tx4.toPSBT();
// Given the above updated PSBT, a signer with the following keys:
// cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au (m/0'/0'/1')
// cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE (m/0'/0'/3')
const tx5 = btc.Transaction.fromPSBT(psbt3);
tx5.sign(btc.WIF(testnet).decode('cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au'));
tx5.sign(btc.WIF(testnet).decode('cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE'));
// must create this PSBT:
const psbt5 = tx5.toPSBT();
// Given both of the above PSBTs, a combiner must create this PSBT:
const psbt6 = btc.PSBTCombine([psbt4, psbt5]);
// Given the above PSBT, an input finalizer must create this PSBT:
const tx7 = btc.Transaction.fromPSBT(psbt6);
tx7.finalize();
const psbt7 = tx7.toPSBT();
// Given the above PSBT, a transaction extractor must create this Bitcoin transaction:
const tx8 = btc.Transaction.fromPSBT(psbt7);
deepStrictEqual(
  tx8.extract(),
  hex.decode(
    '0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000'
  )
);
```

## Utils

### getAddress

Returns common addresses from privateKey

```ts
const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
deepStrictEqual(btc.getAddress('pkh', privKey), '1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD'); // P2PKH (legacy address)
deepStrictEqual(btc.getAddress('wpkh', privKey), 'bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw'); // SegWit V0 address
deepStrictEqual(
  btc.getAddress('tr', priv),
  'bc1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8syx4e5t'
); // TapRoot KeyPathSpend
```

#### WIF

Encoding/decoding of WIF privateKeys. Only compessed keys are supported for now.

```ts
const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
deepStrictEqual(btc.WIF().encode(privKey), 'KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH');
deepStrictEqual(
  hex.encode(btc.WIF().decode('KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH')),
  '0101010101010101010101010101010101010101010101010101010101010101'
);
```

### Script

Encoding/decoding bitcoin scripts

```ts
deepStrictEqual(
  btc.Script.decode(
    hex.decode(
      '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
    )
  ).map((i) => (P.isBytes(i) ? hex.encode(i) : i)),
  [
    'OP_2',
    '030000000000000000000000000000000000000000000000000000000000000001',
    '030000000000000000000000000000000000000000000000000000000000000002',
    '030000000000000000000000000000000000000000000000000000000000000003',
    'OP_3',
    'CHECKMULTISIG',
  ]
);
deepStrictEqual(
  hex.encode(
    btc.Script.encode([
      'OP_2',
      hex.decode('030000000000000000000000000000000000000000000000000000000000000001'),
      hex.decode('030000000000000000000000000000000000000000000000000000000000000002'),
      hex.decode('030000000000000000000000000000000000000000000000000000000000000003'),
      'OP_3',
      'CHECKMULTISIG',
    ])
  ),
  '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
);
```

### OutScript

Encoding / decoding of output scripts

```ts
deepStrictEqual(
  btc.OutScript.decode(
    hex.decode(
      '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
    )
  ),
  {
    type: 'ms',
    m: 2,
    pubkeys: [
      '030000000000000000000000000000000000000000000000000000000000000001',
      '030000000000000000000000000000000000000000000000000000000000000002',
      '030000000000000000000000000000000000000000000000000000000000000003',
    ].map(hex.decode),
  }
);
deepStrictEqual(
  hex.encode(
    btc.OutScript.encode({
      type: 'ms',
      m: 2,
      pubkeys: [
        '030000000000000000000000000000000000000000000000000000000000000001',
        '030000000000000000000000000000000000000000000000000000000000000002',
        '030000000000000000000000000000000000000000000000000000000000000003',
      ].map(hex.decode),
    })
  ),
  '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
);
```

## Security

The library has been independently audited:

- at version 0.3.0, in Feb 2023, by [cure53](https://cure53.de)
  - PDFs: [online](https://cure53.de/audit-report_micro-btc-signer.pdf), [offline](./audit/2023-02-21-cure53-audit-report.pdf)
  - [Changes since audit](https://github.com/paulmillr/scure-btc-signer/compare/0.3.0..main).
  - The audit has been funded by [Ryan Shea](https://shea.io)

### Supply chain security

1. **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures.
2. **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
3. **Rare releasing** is followed.
   The less often it is done, the less code dependents would need to audit
4. **Dependencies** are minimal:
   - All deps are prevented from automatic updates and have locked-down version ranges. Every update is checked with `npm-diff`
   - Updates themselves are rare, to ensure rogue updates are not catched accidentally
   - [noble-hashes](https://github.com/paulmillr/noble-hashes) provides hashing functionality
   - [noble-curves](https://github.com/paulmillr/noble-curves) provides elliptic curve cryptography
   - [scure-base](https://github.com/paulmillr/scure-base) provides bech32 / base64
   - [micro-packed](https://github.com/paulmillr/micro-packed) provides binary encoding - it has not been audited
5. devDependencies are only used if you want to contribute to the repo. They are disabled for end-users:
   - scure-bip32, micro-packed-debugger and micro-should are developed by the same author and follow identical security practices
   - prettier (linter), fast-check (property-based testing) and typescript are used for code quality, vector generation and ts compilation. The packages are big, which makes it hard to audit their source code thoroughly and fully

We consider infrastructure attacks like rogue NPM modules very important;
that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings.
If your app uses 500 dependencies, any dep could get hacked and you'll be
downloading malware with every install. Our goal is to minimize this attack vector.

If you see anything unusual: investigate and report.

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.

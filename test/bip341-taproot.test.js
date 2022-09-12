import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { hex } from '@scure/base';
import * as btc from '../index.js';
import { default as v341 } from './fixtures/bip341.json' assert { type: 'json' };
import * as secp256k1 from '@noble/secp256k1';

for (let i = 0; i < v341.keyPathSpending.length; i++) {
  const t = v341.keyPathSpending[i];
  should(`BIP341: TapRoot keyPathSpending(${i})`, () => {
    // should not be here
    // ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b
    // should be
    // OP_CHECKSIG OP_BOOLAND OP_EQUAL 0xf5 OP_9 75 0xac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b
    // looks kinda broken
    const opts = {
      allowUnknowOutput: i === 0,
      disableScriptCheck: i === 0,
    };
    const tx = btc.Transaction.fromRaw(hex.decode(t.given.rawUnsignedTx), opts);
    const _auxRand = new Uint8Array(32);
    // Inject utxo information
    for (let i = 0; i < t.given.utxosSpent.length; i++) {
      const utxo = t.given.utxosSpent[i];
      const script = hex.decode(utxo.scriptPubKey);
      const amount = BigInt(utxo.amountSats);
      tx.updateInput(i, { witnessUtxo: { amount, script } });
    }
    for (const s of t.inputSpending) {
      const idx = s.given.txinIndex;
      const priv = hex.decode(s.given.internalPrivkey);
      const pub = secp256k1.schnorr.getPublicKey(priv);
      deepStrictEqual(hex.encode(pub), s.intermediary.internalPubkey);
      tx.updateInput(idx, {
        tapMerkleRoot: s.given.merkleRoot,
        tapInternalKey: pub,
        sighashType: s.given.hashType,
      });
      const sighash = s.given.hashType ? [s.given.hashType] : undefined;
      tx.signIdx(priv, idx, sighash, _auxRand);
      deepStrictEqual(hex.encode(tx.inputs[idx].tapKeySig), s.expected.witness[0]);
      tx.finalizeIdx(idx);
      deepStrictEqual(tx.inputs[idx].finalScriptWitness.map(hex.encode), s.expected.witness);
    }
    // txId=2 is not signed, but has pkh input for which we don't have key.
    // These vectors inside BIPs is so awesome.
    const real = btc.Transaction.fromRaw(hex.decode(t.auxiliary.fullySignedTx), opts);
    tx.inputs[2].finalScriptSig = real.inputs[2].finalScriptSig;
    tx.inputs[5].finalScriptWitness = real.inputs[5].finalScriptWitness;
    deepStrictEqual(tx.hex, t.auxiliary.fullySignedTx);
  });
}

should('BIP341: Taproot controlBlock', () => {
  const vectors = [
    {
      leaf: 192,
      neg: 1,
      internal: '187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27',
      branch: '',
      all: 'c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27',
    },
    {
      leaf: 192,
      neg: 0,
      internal: '93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820',
      branch: '',
      all: 'c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820',
    },
    {
      leaf: 192,
      neg: 0,
      internal: 'ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592',
      branch: 'f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a',
      all: 'c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a',
    },
    {
      leaf: 250,
      neg: 0,
      internal: 'ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592',
      branch: '8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7',
      all: 'faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7',
    },
    {
      leaf: 192,
      neg: 1,
      internal: 'f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8',
      branch: '2cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb',
      all: 'c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd82cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb',
    },
    {
      leaf: 192,
      neg: 1,
      internal: 'f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8',
      branch: '64512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89',
      all: 'c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd864512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89',
    },
    {
      leaf: 192,
      neg: 0,
      internal: 'e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f',
      branch: 'ffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553',
      all: 'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553',
    },
    {
      leaf: 192,
      neg: 0,
      internal: 'e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f',
      branch:
        '9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817',
      all: 'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817',
    },
    {
      leaf: 192,
      neg: 0,
      internal: 'e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f',
      branch:
        'ba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817',
      all: 'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817',
    },
    {
      leaf: 192,
      neg: 1,
      internal: '55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d',
      branch: '3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91',
      all: 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91',
    },
    {
      leaf: 192,
      neg: 1,
      internal: '55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d',
      branch:
        'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d',
      all: 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d',
    },
    {
      leaf: 192,
      neg: 1,
      internal: '55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d',
      branch:
        '737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d',
      all: 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d',
    },
  ];
  for (const v of vectors) {
    const merkle = hex.decode(v.branch);
    const chunks = [];
    for (let i = 0; i < merkle.length; i += 32) {
      chunks.push(merkle.slice(i, i + 32));
    }
    deepStrictEqual(
      hex.encode(
        btc.TaprootControlBlock.encode({
          // Another ugly and strange encoding inside btc:
          // they use leaf version with shift and add negation flag to emulate bitset.
          // However it is very easy to break things here
          version: v.leaf + v.neg,
          internalKey: hex.decode(v.internal),
          merklePath: chunks,
        })
      ),
      v.all
    );
  }
});

for (let i = 0; i < v341.scriptPubKey.length; i++) {
  const v = v341.scriptPubKey[i];
  should(`BIP341: TapRoot Script(${i})`, () => {
    const res = btc.p2tr(v.given.internalPubkey, v.given.scriptTree, undefined, true);
    deepStrictEqual(hex.encode(res.tapMerkleRoot), v.intermediary.merkleRoot || '');
    deepStrictEqual(hex.encode(res.tweakedPubkey), v.intermediary.tweakedPubkey);
    deepStrictEqual(
      res.leaves?.map((l) => hex.encode(l.hash)),
      v.intermediary.leafHashes
    );
    deepStrictEqual(
      res.leaves?.map((l) => hex.encode(l.controlBlock)),
      v.expected.scriptPathControlBlocks
    );
    deepStrictEqual(hex.encode(res.script), v.expected.scriptPubKey);
    deepStrictEqual(res.address, v.expected.bip350Address);
  });
}

should('BIP341: TaprootListToTree', () => {
  // Single
  deepStrictEqual(btc.taprootListToTree([{ script: 1 }]), { script: 1 });
  // Simple (balanced binary tree)
  deepStrictEqual(
    btc.taprootListToTree([{ script: 1 }, { script: 2 }, { script: 3 }, { script: 4 }]),
    [
      [{ script: 3 }, { script: 4 }],
      [{ script: 1 }, { script: 2 }],
    ]
  );
  // With weight (reduce path to nodes with high weight)
  deepStrictEqual(
    btc.taprootListToTree([
      { script: 1 },
      { script: 2, weight: 3 },
      { script: 3 },
      { script: 4, weight: 5 },
    ]),
    [{ script: 4, weight: 5 }, [{ script: 2, weight: 3 }, [{ script: 1 }, { script: 3 }]]]
  );
});

should('verify unspendable key', () => {
  deepStrictEqual(
    hex.encode(btc.TAPROOT_UNSPENDABLE_KEY),
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
  );
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

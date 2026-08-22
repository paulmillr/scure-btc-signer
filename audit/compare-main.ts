import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import * as work from '../src/index.ts';
import * as workPsbt from '../src/psbt.ts';
import * as workUtils from '../src/utils.ts';

// Keep the oracle outside this checkout so package imports cannot accidentally resolve to work.
const MAIN = process.env.SCURE_BTC_MAIN_DIR;
if (!MAIN) throw new Error('expected SCURE_BTC_MAIN_DIR to point to a main-branch checkout');
const main = (await import(MAIN + '/src/index.ts')) as typeof work;
const mainPsbt = (await import(MAIN + '/src/psbt.ts')) as typeof workPsbt;
const mainUtils = (await import(MAIN + '/src/utils.ts')) as typeof workUtils;

type Side = {
  name: 'main' | 'work';
  btc: typeof work;
  psbt: typeof workPsbt;
  utils: typeof workUtils;
};
type Tx = InstanceType<typeof work.Transaction>;
type Attempt<T> = { ok: true; value: T } | { ok: false; error: string };
type Kind = 'candidate' | 'intentional' | 'legacy' | 'fingerprint';

const sides: Side[] = [
  { name: 'main', btc: main, psbt: mainPsbt, utils: mainUtils },
  { name: 'work', btc: work, psbt: workPsbt, utils: workUtils },
];
const byName = Object.fromEntries(sides.map((side) => [side.name, side])) as Record<
  Side['name'],
  Side
>;
const priv = new Uint8Array(32).fill(7);
const pub = workUtils.pubECDSA(priv);
const amount = 10_000n;
const findings = new Map<string, { kind: Kind; evidence: string[] }>();
let checks = 0;

const attempt = <T>(fn: () => T): Attempt<T> => {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
};
const same = (a: Uint8Array, b: Uint8Array) => workUtils.equalBytes(a, b);
const addFinding = (kind: Kind, name: string, evidence: string): void => {
  const finding = findings.get(name) || { kind, evidence: [] };
  if (finding.evidence.length < 6) finding.evidence.push(evidence);
  findings.set(name, finding);
};
const check = (
  condition: boolean,
  name: string,
  evidence: string,
  kind: Kind = 'candidate'
): void => {
  checks++;
  if (!condition) addFinding(kind, name, evidence);
};
const error = <T>(result: Attempt<T>): string => (result.ok ? 'ok' : result.error);

const version = (side: Side, bytes: Uint8Array): 0 | 2 => {
  if (attempt(() => side.psbt.RawPSBTV0.decode(bytes)).ok) return 0;
  side.psbt.RawPSBTV2.decode(bytes);
  return 2;
};
const rawV2 = (bytes: Uint8Array) => workPsbt.RawPSBTV2.decode(bytes);
const flags = (bytes: Uint8Array): number | undefined => rawV2(bytes).global.txModifiable;
const parse = (side: Side, bytes: Uint8Array, opts = {}): Tx =>
  side.btc.Transaction.fromPSBT(bytes, opts) as Tx;
const serialize = (side: Side, tx: Tx, psbtVersion: 0 | 2): Uint8Array => tx.toPSBT(psbtVersion);
const relay = (
  side: Side,
  bytes: Uint8Array,
  action: (tx: Tx, side: Side) => void,
  opts = {}
): Attempt<Uint8Array> =>
  attempt(() => {
    const psbtVersion = version(side, bytes);
    const tx = parse(side, bytes, opts);
    action(tx, side);
    return serialize(side, tx, psbtVersion);
  });
const describe = (side: Side, bytes: Uint8Array, opts = {}) => {
  const tx = parse(side, bytes, opts);
  return {
    version: version(side, bytes),
    unsignedTx: hex.encode(tx.unsignedTx),
    lockTime: tx.lockTime,
    inputs: tx.inputsLength,
    outputs: tx.outputsLength,
    final: tx.isFinal,
  };
};

const simple = (side: Side, psbtVersion: 0 | 2, sighash = side.btc.SigHash.ALL) => {
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
  const tx = new side.btc.Transaction({ PSBTVersion: psbtVersion });
  tx.addInput({
    txid: new Uint8Array(32).fill(1),
    index: 0,
    witnessUtxo: { amount, script: spend.script },
    sighashType: sighash,
  });
  tx.addOutput({ amount: amount - 1_000n, script: spend.script });
  return tx.toPSBT(psbtVersion);
};
const addInput = (tx: Tx, side: Side): void => {
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
  tx.addInput({
    txid: new Uint8Array(32).fill(2),
    index: 0,
    witnessUtxo: { amount: 2_000n, script: spend.script },
  });
};
const addOutput = (tx: Tx, side: Side): void => {
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
  tx.addOutput({ amount: 1_000n, script: spend.script });
};
const continuations = (side: Side, bytes: Uint8Array) => ({
  input: relay(side, bytes, addInput).ok,
  output: relay(side, bytes, addOutput).ok,
});

console.log('== ordinary serialized relay ==');
for (const creator of sides) {
  for (const psbtVersion of [0, 2] as const) {
    const bytes = simple(creator, psbtVersion);
    for (const consumer of sides) {
      const observed = attempt(() => describe(consumer, bytes));
      check(
        observed.ok && observed.value.unsignedTx === describe(creator, bytes).unsignedTx,
        'ordinary PSBT relay changes the unsigned transaction',
        `${creator.name} v${psbtVersion} -> ${consumer.name}: ${error(observed)}`
      );
    }
  }
}

console.log('== empty/input/output shape relay ==');
const shaped = (side: Side, psbtVersion: 0 | 2, inputs: number, outputs: number) => {
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
  const tx = new side.btc.Transaction({ PSBTVersion: psbtVersion });
  for (let i = 0; i < inputs; i++)
    tx.addInput({
      txid: new Uint8Array(32).fill(i + 20),
      index: 0,
      witnessUtxo: { amount, script: spend.script },
    });
  for (let i = 0; i < outputs; i++)
    tx.addOutput({ amount: amount - 1_000n - BigInt(i), script: spend.script });
  return tx.toPSBT(psbtVersion);
};
for (const creator of sides) {
  for (const consumer of sides) {
    for (const psbtVersion of [0, 2] as const) {
      for (const [inputs, outputs] of [
        [0, 0],
        [0, 1],
        [1, 0],
        [1, 1],
      ] as const) {
        const bytes = attempt(() => shaped(creator, psbtVersion, inputs, outputs));
        const observed = bytes.ok ? attempt(() => describe(consumer, bytes.value)) : bytes;
        check(
          observed.ok && observed.value.inputs === inputs && observed.value.outputs === outputs,
          'PSBT map counts cannot cross versions',
          `${creator.name} v${psbtVersion} ${inputs}/${outputs} -> ${consumer.name}: ${error(
            observed
          )}`
        );
        const roundtrip = bytes.ok ? relay(consumer, bytes.value, () => {}) : bytes;
        const sizes =
          roundtrip.ok && bytes.ok
            ? `${bytes.value.length}/${roundtrip.value.length}`
            : error(roundtrip);
        check(
          roundtrip.ok && bytes.ok && same(roundtrip.value, bytes.value),
          'main and work map-shape relays produce different PSBT bytes',
          `${creator.name} v${psbtVersion} ${inputs}/${outputs} -> ${consumer.name}: ${sizes}`,
          'fingerprint'
        );
      }
    }
  }
}

console.log('== main-produced field-less PSBTv2 upgrade ==');
const mainV2 = simple(byName.main, 2);
for (const action of [addInput, addOutput]) {
  const mainResult = relay(byName.main, mainV2, action);
  const strictResult = relay(byName.work, mainV2, action);
  const compatResult = relay(byName.work, mainV2, action, { allowMissingTxModifiable: true });
  check(
    mainResult.ok && strictResult.ok,
    'strict work cannot continue constructing a main-produced PSBTv2',
    `${action.name}: main=${error(mainResult)}, work=${error(strictResult)}`,
    'intentional'
  );
  check(
    mainResult.ok && compatResult.ok,
    'compatibility option cannot continue a main-produced PSBTv2',
    `${action.name}: main=${error(mainResult)}, compat=${error(compatResult)}`
  );
  check(
    mainResult.ok && compatResult.ok && same(mainResult.value, compatResult.value),
    'main and compatibility-mode work mutation produce different PSBT bytes',
    `${action.name}: main=${error(mainResult)}, compat=${error(compatResult)}`,
    'fingerprint'
  );
}
const mainDowngrade = attempt(() => parse(byName.main, mainV2).toPSBT(0));
const workDowngrade = attempt(() => parse(byName.work, mainV2).toPSBT(0));
const compatDowngrade = attempt(() =>
  parse(byName.work, mainV2, { allowMissingTxModifiable: true }).toPSBT(0)
);
check(
  mainDowngrade.ok && workDowngrade.ok,
  'strict work cannot downgrade a main-produced PSBTv2',
  `main=${error(mainDowngrade)}, work=${error(workDowngrade)}`,
  'intentional'
);
check(
  compatDowngrade.ok,
  'compatibility option cannot downgrade a main-produced PSBTv2',
  error(compatDowngrade)
);
check(
  mainDowngrade.ok && compatDowngrade.ok && same(mainDowngrade.value, compatDowngrade.value),
  'main and compatibility-mode work downgrade produce different PSBT bytes',
  `main=${error(mainDowngrade)}, compat=${error(compatDowngrade)}`,
  'fingerprint'
);

console.log('== work mutability policy consumed by main ==');
const mutableV2 = simple(byName.work, 2);
const policyFingerprints: string[] = [];
for (const policy of [0, 1, 2, 3] as const) {
  const raw = rawV2(mutableV2);
  raw.global.txModifiable = policy;
  const bytes = workPsbt.RawPSBTV2.encode(raw);
  for (const [bit, action] of [
    [1, addInput],
    [2, addOutput],
  ] as const) {
    const mainResult = relay(byName.main, bytes, action);
    const workResult = relay(byName.work, bytes, action);
    if (policy & bit) {
      if (mainResult.ok && workResult.ok && !same(mainResult.value, workResult.value))
        policyFingerprints.push(`policy=${policy}, ${action.name}`);
      continue;
    }
    check(
      !mainResult.ok && !workResult.ok,
      'main ignores work PSBTv2 transaction-modifiable policy',
      `policy=${policy}, ${action.name}: main=${error(mainResult)}, work=${error(workResult)}`,
      'legacy'
    );
  }
}
check(
  policyFingerprints.length === 0,
  'main and work allowed policy mutations produce different PSBT bytes',
  policyFingerprints.join('; '),
  'fingerprint'
);
const workDowngradeByMain = attempt(() => parse(byName.main, mutableV2).toPSBT(0));
const workDowngradeByWork = attempt(() => parse(byName.work, mutableV2).toPSBT(0));
check(
  workDowngradeByMain.ok === workDowngradeByWork.ok,
  'main cannot downgrade a mutable work-produced PSBTv2',
  `main=${error(workDowngradeByMain)}, work=${error(workDowngradeByWork)}`,
  'legacy'
);

console.log('== exact wire relay ==');
for (const producer of sides) {
  for (const psbtVersion of [0, 2] as const) {
    const bytes = simple(producer, psbtVersion);
    for (const consumer of sides) {
      const roundtrip = relay(consumer, bytes, () => {});
      check(
        roundtrip.ok && same(roundtrip.value, bytes),
        'ordinary serialized PSBT is not byte-stable across versions',
        `${producer.name} v${psbtVersion} -> ${consumer.name}: ${
          roundtrip.ok ? `${bytes.length}/${roundtrip.value.length} bytes` : roundtrip.error
        }`
      );
    }
  }
}

console.log('== main signing work transaction-modifiable state ==');
for (const [sighash, expected] of [
  [work.SigHash.ALL, 0],
  [work.SigHash.ALL_ANYONECANPAY, 1],
  [work.SigHash.NONE, 2],
  [work.SigHash.NONE_ANYONECANPAY, 3],
  [work.SigHash.SINGLE, 4],
  [work.SigHash.SINGLE_ANYONECANPAY, 5],
] as const) {
  const bytes = simple(byName.work, 2, sighash);
  const mainSigned = relay(byName.main, bytes, (tx) => tx.signIdx(priv, 0, [sighash]));
  const workSigned = relay(byName.work, bytes, (tx) => tx.signIdx(priv, 0, [sighash]));
  check(
    mainSigned.ok && workSigned.ok && same(mainSigned.value, workSigned.value),
    'main and work ECDSA signing produce different PSBT bytes',
    `sighash=${sighash}: main=${mainSigned.ok ? flags(mainSigned.value) : mainSigned.error}, ` +
      `work=${workSigned.ok ? flags(workSigned.value) : workSigned.error}`,
    'fingerprint'
  );
  if (mainSigned.ok) {
    const normalized = relay(byName.work, mainSigned.value, () => {});
    check(
      normalized.ok && workSigned.ok && same(normalized.value, workSigned.value),
      'main-produced signatures do not normalize to work signing bytes',
      `sighash=${sighash}, expected work flags=${expected}, ` +
        `normalized=${normalized.ok ? flags(normalized.value) : normalized.error}`,
      'fingerprint'
    );
  }
  const mainFinalized = relay(byName.main, bytes, (tx) => {
    tx.signIdx(priv, 0, [sighash]);
    tx.finalizeIdx(0);
  });
  const workFinalized = relay(byName.work, bytes, (tx) => {
    tx.signIdx(priv, 0, [sighash]);
    tx.finalizeIdx(0);
  });
  check(
    mainFinalized.ok && workFinalized.ok && same(mainFinalized.value, workFinalized.value),
    'main and work ECDSA finalization produce different PSBT bytes',
    `sighash=${sighash}: ` +
      `main=${mainFinalized.ok ? flags(mainFinalized.value) : mainFinalized.error}, ` +
      `work=${workFinalized.ok ? flags(workFinalized.value) : workFinalized.error}`,
    'fingerprint'
  );
}

console.log('== transaction-modifiable combine matrix ==');
const combineContinuationDifferences: string[] = [];
const combineFingerprints: string[] = [];
for (let a = 0; a < 8; a++) {
  for (let b = 0; b < 8; b++) {
    const left = rawV2(mutableV2);
    const right = rawV2(mutableV2);
    left.global.txModifiable = a;
    right.global.txModifiable = b;
    const leftBytes = workPsbt.RawPSBTV2.encode(left);
    const rightBytes = workPsbt.RawPSBTV2.encode(right);
    const workResult = attempt(() => work.PSBTCombine([leftBytes, rightBytes]));
    const mainResult = attempt(() => main.PSBTCombine([leftBytes, rightBytes]));
    check(
      mainResult.ok && workResult.ok,
      'main and work cannot both combine the same transaction-modifiable PSBTs',
      `a=${a}, b=${b}, main=${error(mainResult)}, work=${error(workResult)}`
    );
    if (!mainResult.ok || !workResult.ok) continue;
    for (const consumer of sides) {
      const fromMain = continuations(consumer, mainResult.value);
      const fromWork = continuations(consumer, workResult.value);
      if (fromMain.input !== fromWork.input || fromMain.output !== fromWork.output)
        combineContinuationDifferences.push(
          `${a}/${b}, ${consumer.name}: main=${JSON.stringify(fromMain)}, ` +
            `work=${JSON.stringify(fromWork)}`
        );
    }
    if (!same(mainResult.value, workResult.value)) combineFingerprints.push(`${a}/${b}`);
  }
}
check(
  combineContinuationDifferences.length === 0,
  'main- and work-combined PSBTs permit different subsequent operations',
  combineContinuationDifferences.join('; '),
  'legacy'
);
check(
  combineFingerprints.length === 0,
  'main and work transaction-modifiable combination produces different PSBT bytes',
  combineFingerprints.join('; '),
  'fingerprint'
);

console.log('== normal cross-version signing matrix ==');
const sighashes = [
  work.SigHash.ALL,
  work.SigHash.NONE,
  work.SigHash.SINGLE,
  work.SigHash.ALL_ANYONECANPAY,
  work.SigHash.NONE_ANYONECANPAY,
  work.SigHash.SINGLE_ANYONECANPAY,
];
let normalSigningFailures = 0;
for (const psbtVersion of [0, 2] as const) {
  for (const sighash of sighashes) {
    const expected = (() => {
      const tx = parse(byName.work, simple(byName.work, psbtVersion, sighash));
      tx.signIdx(priv, 0, [sighash]);
      tx.finalizeIdx(0);
      return tx.extract();
    })();
    for (const creator of sides) {
      for (const signer of sides) {
        for (const finalizer of sides) {
          const result = attempt(() => {
            const tx = parse(signer, simple(creator, psbtVersion, sighash));
            tx.signIdx(priv, 0, [sighash]);
            const signed = serialize(signer, tx, psbtVersion);
            const final = parse(finalizer, signed);
            final.finalizeIdx(0);
            return final.extract();
          });
          if (!result.ok || !same(result.value, expected)) normalSigningFailures++;
        }
      }
    }
  }
}
check(
  normalSigningFailures === 0,
  'ordinary signing relay differs across main and work',
  `${normalSigningFailures}/96 creator/signer/finalizer workflows failed or changed extraction`
);

console.log('== Taproot key/script-path signing relay ==');
const taproot = (
  side: Side,
  psbtVersion: 0 | 2,
  scriptPath: boolean,
  sighash?: number
): Uint8Array => {
  const tapKey = side.utils.pubSchnorr(priv);
  const payment = scriptPath
    ? side.btc.p2tr(undefined, side.btc.p2tr_pk(tapKey))
    : side.btc.p2tr(tapKey);
  const tx = new side.btc.Transaction({ PSBTVersion: psbtVersion });
  tx.addInput({
    txid: new Uint8Array(32).fill(9),
    index: 0,
    witnessUtxo: { amount, script: payment.script },
    tapInternalKey: payment.tapInternalKey,
    tapMerkleRoot: payment.tapMerkleRoot,
    tapLeafScript: payment.tapLeafScript,
    sighashType: sighash,
  });
  tx.addOutput({ amount: amount - 1_000n, script: payment.script });
  return tx.toPSBT(psbtVersion);
};
let taprootFailures = 0;
const taprootFingerprints: string[] = [];
for (const psbtVersion of [0, 2] as const) {
  for (const scriptPath of [false, true]) {
    for (const creator of sides) {
      const bytes = taproot(creator, psbtVersion, scriptPath);
      for (const consumer of sides) {
        const roundtrip = relay(consumer, bytes, () => {});
        check(
          roundtrip.ok && same(roundtrip.value, bytes),
          'main and work Taproot relays produce different PSBT bytes',
          `${creator.name} v${psbtVersion} scriptPath=${scriptPath} -> ${consumer.name}: ` +
            `${roundtrip.ok ? `${bytes.length}/${roundtrip.value.length}` : roundtrip.error}`,
          'fingerprint'
        );
      }
    }
    for (const sighash of [undefined, ...sighashes]) {
      const bytes = taproot(byName.work, psbtVersion, scriptPath, sighash);
      const allowed = sighash === undefined ? undefined : [sighash];
      const mainSigned = relay(byName.main, bytes, (tx) =>
        tx.signIdx(priv, 0, allowed, new Uint8Array(32))
      );
      const workSigned = relay(byName.work, bytes, (tx) =>
        tx.signIdx(priv, 0, allowed, new Uint8Array(32))
      );
      if (mainSigned.ok && workSigned.ok && !same(mainSigned.value, workSigned.value))
        taprootFingerprints.push(
          `v${psbtVersion} scriptPath=${scriptPath} sighash=${String(sighash)} signer`
        );
      const mainFinal = mainSigned.ok
        ? relay(byName.main, mainSigned.value, (tx) => tx.finalizeIdx(0))
        : mainSigned;
      const workFinal = workSigned.ok
        ? relay(byName.work, workSigned.value, (tx) => tx.finalizeIdx(0))
        : workSigned;
      if (mainFinal.ok && workFinal.ok && !same(mainFinal.value, workFinal.value))
        taprootFingerprints.push(
          `v${psbtVersion} scriptPath=${scriptPath} sighash=${String(sighash)} finalizer`
        );
    }
    const expected = (() => {
      const tx = parse(byName.work, taproot(byName.work, psbtVersion, scriptPath));
      tx.signIdx(priv, 0, undefined, new Uint8Array(32));
      tx.finalizeIdx(0);
      return tx.extract();
    })();
    for (const creator of sides) {
      for (const signer of sides) {
        for (const finalizer of sides) {
          const result = attempt(() => {
            const tx = parse(signer, taproot(creator, psbtVersion, scriptPath));
            tx.signIdx(priv, 0, undefined, new Uint8Array(32));
            const signed = serialize(signer, tx, psbtVersion);
            const final = parse(finalizer, signed);
            final.finalizeIdx(0);
            return final.extract();
          });
          if (!result.ok || !same(result.value, expected)) taprootFailures++;
        }
      }
    }
  }
}
check(
  taprootFailures === 0,
  'Taproot signing relay differs across main and work',
  `${taprootFailures}/32 key-path/script-path workflows failed or changed extraction`
);
check(
  taprootFingerprints.length === 0,
  'main and work Taproot signing/finalization produce different PSBT bytes',
  taprootFingerprints.join('; '),
  'fingerprint'
);

console.log('== PSBTv0/PSBTv2 combination relay ==');
const v0 = simple(byName.work, 0);
const v2 = simple(byName.work, 2);
for (const pair of [
  [v0, v2],
  [v2, v0],
]) {
  const combined = new Map(
    sides.map((combiner) => [combiner.name, attempt(() => combiner.btc.PSBTCombine(pair))])
  );
  for (const combiner of sides) {
    const result = combined.get(combiner.name)!;
    check(
      result.ok &&
        version(byName.work, result.value) === 2 &&
        describe(byName.work, result.value).unsignedTx === describe(byName.work, v0).unsignedTx,
      'ordinary PSBTv0/PSBTv2 combination is not interoperable',
      `${combiner.name}, order=${version(byName.work, pair[0])}/${version(
        byName.work,
        pair[1]
      )}: ${error(result)}`
    );
  }
  const mainCombined = combined.get('main')!;
  const workCombined = combined.get('work')!;
  check(
    mainCombined.ok && workCombined.ok && same(mainCombined.value, workCombined.value),
    'main and work unsigned v0/v2 combination produce different PSBT bytes',
    `order=${version(byName.work, pair[0])}/${version(byName.work, pair[1])}: ` +
      `main=${error(mainCombined)}, work=${error(workCombined)}`,
    'fingerprint'
  );
}
const signedV0 = relay(byName.work, v0, (tx) => tx.signIdx(priv, 0));
if (!signedV0.ok) throw new Error(signedV0.error);
for (const pair of [
  [signedV0.value, v2],
  [v2, signedV0.value],
]) {
  const mainCombined = attempt(() => main.PSBTCombine(pair));
  const workCombined = attempt(() => work.PSBTCombine(pair));
  for (const [name, combined] of [
    ['main', mainCombined],
    ['work', workCombined],
  ] as const) {
    check(
      combined.ok &&
        version(byName.work, combined.value) === 2 &&
        describe(byName.work, combined.value).unsignedTx === describe(byName.work, v0).unsignedTx,
      'signed v0/v2 combination is not interoperable',
      `${name}, order=${version(byName.work, pair[0])}/${version(
        byName.work,
        pair[1]
      )}: ${error(combined)}`
    );
  }
  check(
    mainCombined.ok && workCombined.ok && same(mainCombined.value, workCombined.value),
    'main and work signed v0/v2 combination produce different PSBT bytes',
    `order=${version(byName.work, pair[0])}/${version(byName.work, pair[1])}: ` +
      `main=${error(mainCombined)}, work=${error(workCombined)}`,
    'fingerprint'
  );
}

console.log('== externally encoded signature scope relay ==');
const unsignedSighash = (sighash?: number): Uint8Array => {
  const spend = work.p2wpkh(pub);
  const tx = new work.Transaction({ PSBTVersion: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(10),
    index: 0,
    witnessUtxo: { amount, script: spend.script },
    sighashType: sighash,
  });
  tx.addOutput({ amount: amount - 1_000n, script: spend.script });
  tx.signIdx(priv, 0, sighash === undefined ? undefined : [sighash]);
  return tx.toPSBT(2);
};
const witnessSigValid = (bytes: Uint8Array): boolean => {
  const tx = parse(byName.work, bytes);
  const sig = tx.getInput(0).partialSig![0][1];
  const sighash = sig[sig.length - 1];
  const digest = tx.preimageWitnessV0(0, work.p2pkh(pub).script, sighash, amount);
  return secp256k1.verify(sig.subarray(0, -1), digest, pub, {
    format: 'der',
    lowS: false,
    prehash: false,
  });
};
const signatureResult = (result: Attempt<Uint8Array>): string =>
  result.ok ? `signature valid=${witnessSigValid(result.value)}` : result.error;
const signedWithoutType = unsignedSighash();
for (const consumer of sides) {
  const changed = relay(consumer, signedWithoutType, (tx, side) => {
    tx.updateInput(0, { sighashType: side.btc.SigHash.NONE });
    addOutput(tx, side);
  });
  check(
    !changed.ok,
    'main appends a contradictory sighash type and invalidates a relayed signature',
    `${consumer.name}: ${signatureResult(changed)}`,
    consumer.name === 'main' ? 'legacy' : 'candidate'
  );
}
for (const consumer of sides) {
  const changed = relay(consumer, signedWithoutType, (tx) => {
    tx.updateInput(0, { requiredHeightLocktime: 123 });
  });
  check(
    !changed.ok,
    'main appends a locktime requirement and invalidates a relayed signature',
    `${consumer.name}: ${signatureResult(changed)}`,
    consumer.name === 'main' ? 'legacy' : 'candidate'
  );
}
const anyoneSigned = unsignedSighash(work.SigHash.ALL_ANYONECANPAY);
for (const consumer of sides) {
  const changed = relay(consumer, anyoneSigned, (tx, side) => {
    const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
    tx.addInput({
      txid: new Uint8Array(32).fill(11),
      index: 0,
      witnessUtxo: { amount: 2_000n, script: spend.script },
      requiredHeightLocktime: 123,
    });
  });
  check(
    !changed.ok,
    'main adds an input whose locktime requirement invalidates an ANYONECANPAY signature',
    `${consumer.name}: ${signatureResult(changed)}`,
    consumer.name === 'main' ? 'legacy' : 'candidate'
  );
}

console.log('== signature-byte-only mutation matrix ==');
const signatureMutationFingerprints: string[] = [];
for (const sighash of sighashes) {
  const raw = rawV2(unsignedSighash(sighash));
  delete raw.inputs[0].sighashType;
  const bytes = workPsbt.RawPSBTV2.encode(raw);
  // SigHash exports complete modes rather than the standalone protocol mask.
  const allowInput = !!(sighash & 0x80);
  const outputMode = sighash & 3;
  // This fixture already has the output paired with input zero. SIGHASH_SINGLE commits to that
  // existing output, but not to a later append, so both NONE and SINGLE permit addOutput here.
  const allowOutput = outputMode === work.SigHash.NONE || outputMode === work.SigHash.SINGLE;
  for (const [allowed, action] of [
    [allowInput, addInput],
    [allowOutput, addOutput],
  ] as const) {
    const mainResult = relay(byName.main, bytes, action);
    const workResult = relay(byName.work, bytes, action);
    for (const [consumer, changed] of [
      [byName.main, mainResult],
      [byName.work, workResult],
    ] as const) {
      check(
        changed.ok === allowed && (!changed.ok || witnessSigValid(changed.value)),
        'main cannot continue a valid signature-byte-only mutation scope',
        `${consumer.name}, sighash=${sighash}, ${action.name}: expected=${allowed}, actual=${
          changed.ok
        }${changed.ok ? `, signature valid=${witnessSigValid(changed.value)}` : ''}`,
        consumer.name === 'main' ? 'legacy' : 'candidate'
      );
    }
    if (mainResult.ok && workResult.ok && !same(mainResult.value, workResult.value))
      signatureMutationFingerprints.push(`sighash=${sighash}, ${action.name}`);
  }
}
check(
  signatureMutationFingerprints.length === 0,
  'main and work allowed signed mutations produce different PSBT bytes',
  signatureMutationFingerprints.join('; '),
  'fingerprint'
);

console.log('== required-locktime finalization relay ==');
type Requirement = {
  requiredHeightLocktime?: number;
  requiredTimeLocktime?: number;
};
const lockShape = (side: Side, fallbackLocktime: number, requirements: Requirement[]) => {
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
  const tx = new side.btc.Transaction({ PSBTVersion: 2, lockTime: fallbackLocktime });
  for (let i = 0; i < requirements.length; i++)
    tx.addInput({
      txid: new Uint8Array(32).fill(i + 30),
      index: 0,
      sequence: 0xfffffffe,
      witnessUtxo: { amount, script: spend.script },
      ...requirements[i],
    });
  tx.addOutput({ amount: amount - 1_000n, script: spend.script });
  return tx.toPSBT(2);
};
for (const [fallbackLocktime, requirements, expected] of [
  [77, [{}, {}], 77],
  [0, [{ requiredHeightLocktime: 100 }, { requiredHeightLocktime: 123 }], 123],
  [
    0,
    [
      { requiredHeightLocktime: 100 },
      { requiredHeightLocktime: 123, requiredTimeLocktime: 600_000_000 },
    ],
    123,
  ],
  [
    0,
    [
      { requiredTimeLocktime: 600_000_000 },
      { requiredHeightLocktime: 123, requiredTimeLocktime: 700_000_000 },
    ],
    700_000_000,
  ],
] as const) {
  for (const creator of sides) {
    const bytes = lockShape(creator, fallbackLocktime, [...requirements]);
    for (const consumer of sides) {
      const observed = attempt(() => parse(consumer, bytes).lockTime);
      check(
        observed.ok && observed.value === expected,
        'valid PSBTv2 locktime domains differ across main and work',
        `${creator.name} -> ${consumer.name}: expected=${expected}, got=${
          observed.ok ? observed.value : observed.error
        }`
      );
      const roundtrip = relay(consumer, bytes, () => {});
      check(
        roundtrip.ok && same(roundtrip.value, bytes),
        'main and work locktime relays produce different PSBT bytes',
        `${creator.name} -> ${consumer.name}: ${error(roundtrip)}`,
        'fingerprint'
      );
    }
  }
}
const incompatibleLocktime = lockShape(byName.main, 0, [
  { requiredHeightLocktime: 123 },
  { requiredTimeLocktime: 600_000_000 },
]);
for (const consumer of sides) {
  const observed = attempt(() => parse(consumer, incompatibleLocktime).lockTime);
  check(
    observed.ok,
    'work rejects main-produced incompatible PSBTv2 locktime domains',
    `${consumer.name}: ${error(observed)}`,
    'intentional'
  );
}

const locktime = (side: Side): Uint8Array => {
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
  const tx = new side.btc.Transaction({ PSBTVersion: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(3),
    index: 0,
    sequence: 0xfffffffe,
    witnessUtxo: { amount, script: spend.script },
    requiredHeightLocktime: 123,
  });
  tx.addOutput({ amount: amount - 1_000n, script: spend.script });
  return tx.toPSBT(2);
};
let locktimeFailures = 0;
const locktimeFingerprints: string[] = [];
for (const creator of sides) {
  for (const signer of sides) {
    const signed = relay(signer, locktime(creator), (tx) => tx.signIdx(priv, 0));
    if (!signed.ok) {
      locktimeFailures++;
      continue;
    }
    const finals = new Map<Side['name'], Attempt<Uint8Array>>();
    for (const finalizer of sides) {
      const finalized = relay(finalizer, signed.value, (tx) => tx.finalizeIdx(0));
      finals.set(finalizer.name, finalized);
      if (!finalized.ok) {
        locktimeFailures++;
        continue;
      }
      const reopened = attempt(() => parse(byName.work, finalized.value).lockTime);
      if (!reopened.ok || reopened.value !== 123) locktimeFailures++;
    }
    const mainFinal = finals.get('main')!;
    const workFinal = finals.get('work')!;
    if (
      mainFinal.ok &&
      workFinal.ok &&
      describe(byName.work, mainFinal.value).lockTime ===
        describe(byName.work, workFinal.value).lockTime &&
      !same(mainFinal.value, workFinal.value)
    )
      locktimeFingerprints.push(`${creator.name} creator, ${signer.name} signer`);
  }
}
check(
  locktimeFailures === 0,
  'main finalization changes the locktime committed by a relayed signature',
  `${locktimeFailures}/8 creator/signer/finalizer workflows lost locktime 123`,
  'legacy'
);
check(
  locktimeFingerprints.length === 0,
  'main and work locktime finalization produce different PSBT bytes',
  locktimeFingerprints.join('; '),
  'fingerprint'
);

const funding = (script: Uint8Array): Uint8Array =>
  work.RawTx.encode({
    version: 2,
    segwitFlag: false,
    inputs: [
      {
        txid: new Uint8Array(32),
        index: 0xffffffff,
        finalScriptSig: Uint8Array.of(0x51),
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ amount, script }],
    witnesses: [],
    lockTime: 0,
  });
const legacy = (side: Side, script: Uint8Array, outputs: number): Uint8Array => {
  const prev = funding(script);
  const tx = new side.btc.Transaction({ PSBTVersion: 0 });
  // Raw hashes are wire-order; TransactionInput.txid follows the repository's display-order API.
  const txid = Uint8Array.from(workUtils.sha256x2(prev)).reverse();
  tx.addInput({ txid, index: 0, nonWitnessUtxo: prev });
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(new Uint8Array(32).fill(8)));
  for (let i = 0; i < outputs; i++)
    tx.addOutput({ amount: amount - 1_000n - BigInt(i), script: spend.script });
  return tx.toPSBT(0);
};
const signature = (side: Side, bytes: Uint8Array, sighash: number): Uint8Array => {
  const tx = parse(side, bytes);
  tx.updateInput(0, { sighashType: sighash });
  tx.signIdx(priv, 0, [sighash]);
  const signed = tx.toPSBT(0);
  return parse(byName.work, signed).getInput(0).partialSig![0][1];
};
const verifies = (
  bytes: Uint8Array,
  script: Uint8Array,
  sig: Uint8Array,
  sighash: number
): boolean => {
  const tx = parse(byName.work, bytes);
  const digest = tx.preimageLegacy(0, script, sighash);
  return secp256k1.verify(sig.subarray(0, -1), digest, pub, {
    format: 'der',
    lowS: false,
    prehash: false,
  });
};

console.log('== exact-script signing relay ==');
const rawPkh = Uint8Array.from([0x76, 0xa9, 0x4c, 0x14, ...workUtils.hash160(pub), 0x88, 0xac]);
const nonminimalBytes = legacy(byName.work, rawPkh, 1);
for (const signer of sides) {
  const sig = signature(signer, nonminimalBytes, work.SigHash.ALL);
  check(
    verifies(nonminimalBytes, rawPkh, sig, work.SigHash.ALL),
    'main signature cannot be consumed for an exact non-minimal script',
    `${signer.name} signature verifies against committed script=${verifies(
      nonminimalBytes,
      rawPkh,
      sig,
      work.SigHash.ALL
    )}`,
    'legacy'
  );
}

console.log('== wrapped exact-script signer/finalizer relay ==');
const rawPk = Uint8Array.from([0x4c, pub.length, ...pub, work.OP.CHECKSIG]);
const wrapped = (side: Side, kind: 'sh' | 'wsh'): Uint8Array => {
  const outputScript =
    kind === 'sh'
      ? Uint8Array.from([work.OP.HASH160, 0x14, ...workUtils.hash160(rawPk), work.OP.EQUAL])
      : Uint8Array.from([0, 0x20, ...workUtils.sha256(rawPk)]);
  const prev = funding(outputScript);
  const txid = Uint8Array.from(workUtils.sha256x2(prev)).reverse();
  const tx = new side.btc.Transaction({ PSBTVersion: 0 });
  tx.addInput({
    txid,
    index: 0,
    nonWitnessUtxo: prev,
    redeemScript: kind === 'sh' ? rawPk : undefined,
    witnessScript: kind === 'wsh' ? rawPk : undefined,
  });
  const spend = side.btc.p2wpkh(side.utils.pubECDSA(new Uint8Array(32).fill(8)));
  tx.addOutput({ amount: amount - 1_000n, script: spend.script });
  return tx.toPSBT(0);
};
let wrappedSignerFailures = 0;
let wrappedFinalizerFailures = 0;
for (const kind of ['sh', 'wsh'] as const) {
  const bytes = wrapped(byName.work, kind);
  for (const signer of sides) {
    const signed = relay(signer, bytes, (tx) => tx.signIdx(priv, 0));
    if (!signed.ok) {
      wrappedSignerFailures++;
      continue;
    }
    for (const finalizer of sides) {
      const finalized = relay(finalizer, signed.value, (tx) => tx.finalizeIdx(0));
      if (!finalized.ok) {
        wrappedFinalizerFailures++;
        continue;
      }
      const input = parse(byName.work, finalized.value).getInput(0);
      const stack =
        kind === 'sh' ? work.Script.decode(input.finalScriptSig!) : input.finalScriptWitness!;
      const finalScript = stack[stack.length - 1];
      const sig = stack[0];
      if (!(finalScript instanceof Uint8Array) || !same(finalScript, rawPk))
        wrappedFinalizerFailures++;
      if (!(sig instanceof Uint8Array)) {
        wrappedSignerFailures++;
        continue;
      }
      const tx = parse(byName.work, bytes);
      const sighash = sig[sig.length - 1];
      const digest =
        kind === 'sh'
          ? tx.preimageLegacy(0, rawPk, sighash)
          : tx.preimageWitnessV0(0, rawPk, sighash, amount);
      if (
        !secp256k1.verify(sig.subarray(0, -1), digest, pub, {
          format: 'der',
          lowS: false,
          prehash: false,
        })
      )
        wrappedSignerFailures++;
    }
  }
}
check(
  wrappedSignerFailures === 0,
  'main wrapped-script signatures cannot be consumed by work',
  `${wrappedSignerFailures}/8 signer/finalizer paths produced an invalid signature`,
  'legacy'
);
check(
  wrappedFinalizerFailures === 0,
  'main finalizer replaces the serialized non-minimal redeem/witness script',
  `${wrappedFinalizerFailures}/8 signer/finalizer paths changed the committed script`,
  'legacy'
);

console.log('== legacy SIGHASH_SINGLE relay ==');
const canonicalPkh = work.p2pkh(pub).script;
const singleBytes = legacy(byName.work, canonicalPkh, 0);
const hashOne = new Uint8Array(32);
hashOne[0] = 1;
for (const consumer of sides) {
  // Both public signers reject this edge, but external signatures still require the consensus
  // digest when a serialized PSBT is inspected or completed by another implementation.
  const digest = parse(consumer, singleBytes).preimageLegacy(0, canonicalPkh, work.SigHash.SINGLE);
  check(
    same(digest, hashOne),
    'main derives a different legacy SIGHASH_SINGLE hash-of-one from serialized PSBT state',
    `${consumer.name} digest=${hex.encode(digest)}`,
    'legacy'
  );
}

console.log('== finalized/partial combination relay ==');
const base = simple(byName.work, 0);
const partial = relay(byName.work, base, (tx) => tx.signIdx(priv, 0));
if (!partial.ok) throw new Error(partial.error);
const finalized = relay(byName.work, partial.value, (tx) => tx.finalizeIdx(0));
if (!finalized.ok) throw new Error(finalized.error);
for (const combiner of sides) {
  for (const pair of [
    [partial.value, finalized.value],
    [finalized.value, partial.value],
  ]) {
    const combined = attempt(() => combiner.btc.PSBTCombine(pair));
    const order = same(pair[0], partial.value) ? 'partial/final' : 'final/partial';
    const clean =
      combined.ok &&
      attempt(() => {
        const input = parse(byName.work, combined.value).getInput(0);
        return !!input.finalScriptWitness && input.partialSig === undefined;
      });
    check(
      !!clean && clean.ok && clean.value,
      'main combination leaves mixed finalized and partial signing state',
      `${combiner.name}, order=${order}: ${
        combined.ok ? (clean.ok ? String(clean.value) : clean.error) : combined.error
      }`,
      'legacy'
    );
  }
}

console.log('== opaque metadata relay ==');
const opaque = rawV2(mutableV2);
const unknown = [[{ type: 0xfd, key: Uint8Array.of(1) }, Uint8Array.of(2)]] as const;
// BIP174 suffix: one-byte identifier 0x03, subtype 4, and no subkey data.
const proprietary = [[Uint8Array.of(1, 3, 4), Uint8Array.of(4)]] as const;
opaque.global.unknown = unknown as never;
opaque.inputs[0].unknown = unknown as never;
opaque.outputs[0].unknown = unknown as never;
opaque.global.proprietary = proprietary as never;
opaque.inputs[0].proprietary = proprietary as never;
opaque.outputs[0].proprietary = proprietary as never;
const opaqueBytes = workPsbt.RawPSBTV2.encode(opaque);
for (const allowUnknown of [false, true]) {
  const relayed = new Map(
    sides.map((consumer) => [
      consumer.name,
      relay(consumer, opaqueBytes, () => {}, { allowUnknown }),
    ])
  );
  for (const consumer of sides) {
    const result = relayed.get(consumer.name)!;
    const retained =
      result.ok &&
      (() => {
        const raw = rawV2(result.value);
        const unknownCount =
          (raw.global.unknown?.length || 0) +
          (raw.inputs[0].unknown?.length || 0) +
          (raw.outputs[0].unknown?.length || 0);
        const proprietaryCount =
          (raw.global.proprietary?.length || 0) +
          (raw.inputs[0].proprietary?.length || 0) +
          (raw.outputs[0].proprietary?.length || 0);
        return { unknownCount, proprietaryCount };
      })();
    check(
      !!retained &&
        retained.unknownCount === (allowUnknown ? 3 : 0) &&
        retained.proprietaryCount === 3,
      'opaque metadata relay differs across main and work',
      `${consumer.name}, allowUnknown=${allowUnknown}: ${
        retained ? JSON.stringify(retained) : error(result)
      }`,
      !allowUnknown && consumer.name === 'main' ? 'intentional' : 'candidate'
    );
  }
  const mainResult = relayed.get('main')!;
  const workResult = relayed.get('work')!;
  if (allowUnknown)
    check(
      mainResult.ok && workResult.ok && same(mainResult.value, workResult.value),
      'main and work opaque-field relay produce different PSBT bytes',
      `main=${error(mainResult)}, work=${error(workResult)}`,
      'fingerprint'
    );
}

console.log('== bip174js empty-map compatibility relay ==');
const compat = (side: Side, input: boolean): Attempt<Uint8Array> =>
  attempt(() => {
    const tx = new side.btc.Transaction({ PSBTVersion: 0, bip174jsCompat: true });
    if (input) {
      const spend = side.btc.p2wpkh(side.utils.pubECDSA(priv));
      tx.addInput({
        txid: new Uint8Array(32).fill(12),
        index: 0,
        witnessUtxo: { amount, script: spend.script },
      });
    }
    return tx.toPSBT(0);
  });
for (const creator of sides) {
  for (const hasInput of [false, true]) {
    const bytes = compat(creator, hasInput);
    // A creator failure has no serialized boundary and is outside this harness's scope.
    if (!bytes.ok) continue;
    for (const consumer of sides) {
      const observed = attempt(() => describe(consumer, bytes.value));
      check(
        observed.ok && observed.value.inputs === Number(hasInput) && observed.value.outputs === 0,
        'bip174js empty-map encoding cannot cross versions',
        `${creator.name}, input=${hasInput} -> ${consumer.name}: ${error(observed)}`
      );
      const roundtrip = relay(consumer, bytes.value, () => {});
      check(
        roundtrip.ok && same(roundtrip.value, bytes.value),
        'bip174js PSBT bytes change during a no-op relay',
        `${creator.name}, input=${hasInput} -> ${consumer.name}: ${error(roundtrip)}`,
        'fingerprint'
      );
    }
  }
}

console.log(`\n${checks} checks, ${findings.size} interoperability findings`);
for (const [name, finding] of findings) {
  console.log(`\n[${finding.kind.toUpperCase()}] ${name}`);
  for (const line of finding.evidence) console.log(`  - ${line}`);
}

export { findings };

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64, hex } from '@scure/base';
import * as btc from '../src/index.ts';
import * as psbt from '../src/psbt.ts';
import * as utils from '../src/utils.ts';

// Build products stay outside this repository; use PATH or an explicit binary path.
const CORE = process.env.BTC_CROSSTEST || 'btc-crosstest';
const CORE_VECTORS =
  process.env.BITCOIN_PSBT_VECTORS ||
  (process.env.BITCOIN_SOURCE_DIR &&
    `${process.env.BITCOIN_SOURCE_DIR}/test/functional/data/rpc_psbt.json`);
if (!CORE_VECTORS)
  throw new Error('expected BITCOIN_SOURCE_DIR or BITCOIN_PSBT_VECTORS for Core PSBT vectors');

type Attempt<T> = { ok: true; value: T } | { ok: false; error: string };
type Kind = 'candidate' | 'intentional' | 'fingerprint';
type Finding = { kind: Kind; context: string; evidence: string[] };
type CoreInfo = {
  psbt_version: number;
  tx_version: number;
  fallback_locktime: number | null;
  tx_modifiable: number | null;
  computed_locktime: number | null;
  inputs: number;
  outputs: number;
  signature_inputs: number;
  final_inputs: number;
  partial_signatures: number;
  unsigned_tx: string | null;
};
type Requirement = {
  requiredHeightLocktime?: number;
  requiredTimeLocktime?: number;
};

const priv = new Uint8Array(32).fill(7);
const privHex = hex.encode(priv);
const pub = utils.pubECDSA(priv);
const amount = 10_000n;
const findings = new Map<string, Finding>();
let checks = 0;

const attempt = <T>(fn: () => T): Attempt<T> => {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
};
const error = <T>(result: Attempt<T>): string => (result.ok ? 'ok' : result.error);
const same = (a: Uint8Array, b: Uint8Array): boolean => utils.equalBytes(a, b);
const addFinding = (kind: Kind, context: string, name: string, evidence: string): void => {
  const finding = findings.get(name) || { kind, context, evidence: [] };
  if (finding.evidence.length < 8) finding.evidence.push(evidence);
  findings.set(name, finding);
};
const check = (
  condition: boolean,
  name: string,
  evidence: string,
  kind: Kind = 'candidate',
  context = 'Serialized interoperability'
): void => {
  checks++;
  if (!condition) addFinding(kind, context, name, evidence);
};

const run = (...args: string[]): Attempt<string> =>
  attempt(() => {
    const result = spawnSync(CORE, args, { encoding: 'utf8' });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      const message = result.stderr.trim() || `exit status ${String(result.status)}`;
      throw new Error(message.replace(/^error: /, ''));
    }
    return result.stdout.trim();
  });
const corePSBT = (command: string, values: Uint8Array[], extra: string[] = []) => {
  const result = run(command, ...values.map(base64.encode), ...extra);
  return result.ok ? attempt(() => base64.decode(result.value)) : result;
};
const coreRoundtrip = (bytes: Uint8Array) => corePSBT('roundtrip', [bytes]);
const coreCombine = (...values: Uint8Array[]) => corePSBT('combine', values);
const coreFinalize = (bytes: Uint8Array) => corePSBT('finalize', [bytes]);
const coreSign = (bytes: Uint8Array, keys = [privHex]) => corePSBT('sign', [bytes], keys);
const coreExtract = (bytes: Uint8Array): Attempt<Uint8Array> => {
  const result = run('extract', base64.encode(bytes));
  return result.ok ? attempt(() => hex.decode(result.value)) : result;
};
const coreInspect = (bytes: Uint8Array): Attempt<CoreInfo> => {
  const result = run('inspect', base64.encode(bytes));
  return result.ok ? attempt(() => JSON.parse(result.value) as CoreInfo) : result;
};
const coreAddInput = (
  bytes: Uint8Array,
  fill: number,
  requirement: Requirement = {}
): Attempt<Uint8Array> =>
  corePSBT(
    'add-input',
    [bytes],
    [
      fill.toString(16).padStart(2, '0').repeat(32),
      '0',
      '4294967294',
      requirement.requiredHeightLocktime?.toString() || '-',
      requirement.requiredTimeLocktime?.toString() || '-',
    ]
  );
const coreAddOutput = (bytes: Uint8Array): Attempt<Uint8Array> =>
  corePSBT('add-output', [bytes], ['1000', hex.encode(btc.p2wpkh(pub).script)]);

const version = (bytes: Uint8Array): 0 | 2 => {
  if (attempt(() => psbt.RawPSBTV0.decode(bytes)).ok) return 0;
  psbt.RawPSBTV2.decode(bytes);
  return 2;
};
const rawV2 = (bytes: Uint8Array) => psbt.RawPSBTV2.decode(bytes);
const flags = (bytes: Uint8Array): number | undefined => rawV2(bytes).global.txModifiable;
const parse = (bytes: Uint8Array, opts = {}) => btc.Transaction.fromPSBT(bytes, opts);
const relay = (
  bytes: Uint8Array,
  action: (tx: btc.Transaction) => void,
  opts = {}
): Attempt<Uint8Array> =>
  attempt(() => {
    const tx = parse(bytes, opts);
    action(tx);
    return tx.toPSBT(version(bytes));
  });
const describe = (bytes: Uint8Array) => {
  const tx = parse(bytes);
  return {
    version: version(bytes),
    txVersion: tx.version,
    lockTime: tx.lockTime,
    inputs: tx.inputsLength,
    outputs: tx.outputsLength,
    unsignedTx: hex.encode(tx.unsignedTx),
    final: tx.isFinal,
  };
};
const simple = (psbtVersion: 0 | 2, sighash = btc.SigHash.ALL): Uint8Array => {
  const spend = btc.p2wpkh(pub);
  const tx = new btc.Transaction({ PSBTVersion: psbtVersion });
  tx.addInput({
    txid: new Uint8Array(32).fill(1),
    index: 0,
    witnessUtxo: { amount, script: spend.script },
    sighashType: sighash,
  });
  tx.addOutput({ amount: amount - 1_000n, script: spend.script });
  return tx.toPSBT(psbtVersion);
};
const workAddInput = (tx: btc.Transaction, requirement: Requirement = {}): void => {
  tx.addInput({
    txid: new Uint8Array(32).fill(2),
    index: 0,
    sequence: 0xfffffffe,
    witnessUtxo: { amount: 2_000n, script: btc.p2wpkh(pub).script },
    ...requirement,
  });
};
const workAddOutput = (tx: btc.Transaction): void => {
  tx.addOutput({ amount: 1_000n, script: btc.p2wpkh(pub).script });
};
const transientTaprootFields = (bytes: Uint8Array): string[] => {
  const input = parse(bytes, { allowUnknown: true }).getInput(0);
  return [
    'tapKeySig',
    'tapScriptSig',
    'tapLeafScript',
    'tapBip32Derivation',
    'tapInternalKey',
    'tapMerkleRoot',
  ].filter((name) => input[name as keyof typeof input] !== undefined);
};
const finalizedByWork = (bytes: Uint8Array): Attempt<Uint8Array> =>
  relay(bytes, (tx) => tx.finalize());
const extractedByWork = (bytes: Uint8Array): Attempt<Uint8Array> =>
  attempt(() => parse(bytes).extract());

console.log('== bridge and ordinary serialized relay ==');
const bridgeVersion = run('version');
check(
  bridgeVersion.ok && bridgeVersion.value === '2',
  'native bridge does not expose the expected PSBTv2 implementation',
  error(bridgeVersion)
);
for (const psbtVersion of [0, 2] as const) {
  const bytes = simple(psbtVersion);
  const info = coreInspect(bytes);
  const roundtrip = coreRoundtrip(bytes);
  const observed = roundtrip.ok ? attempt(() => describe(roundtrip.value)) : roundtrip;
  check(
    info.ok &&
      observed.ok &&
      info.value.psbt_version === psbtVersion &&
      info.value.unsigned_tx === observed.value.unsignedTx &&
      info.value.inputs === 1 &&
      info.value.outputs === 1,
    'ordinary PSBT semantics differ after a Core relay',
    `v${psbtVersion}: inspect=${error(info)}, work=${error(observed)}`
  );
  const size = roundtrip.ok ? `${bytes.length}/${roundtrip.value.length}` : roundtrip.error;
  check(
    roundtrip.ok && same(roundtrip.value, bytes),
    'ordinary canonical PSBT bytes change during a Core round-trip',
    `v${psbtVersion}: ${size}`,
    'fingerprint',
    'Semantically equivalent serialized output'
  );
}

console.log('== input/output map shapes ==');
for (const psbtVersion of [0, 2] as const) {
  for (const [inputs, outputs] of [
    [0, 0],
    [0, 1],
    [1, 0],
    [1, 1],
  ] as const) {
    const created = attempt(() => {
      const tx = new btc.Transaction({ PSBTVersion: psbtVersion });
      for (let i = 0; i < inputs; i++)
        tx.addInput({
          txid: new Uint8Array(32).fill(i + 20),
          index: 0,
          witnessUtxo: { amount, script: btc.p2wpkh(pub).script },
        });
      for (let i = 0; i < outputs; i++)
        tx.addOutput({ amount: amount - 1_000n - BigInt(i), script: btc.p2wpkh(pub).script });
      return tx.toPSBT(psbtVersion);
    });
    // Creator failures have no serialized boundary, so they are outside this comparison.
    if (!created.ok) continue;
    const info = coreInspect(created.value);
    check(
      info.ok && info.value.inputs === inputs && info.value.outputs === outputs,
      'Core cannot consume a serialized scure PSBT map shape',
      `v${psbtVersion} ${inputs}/${outputs}: ${error(info)}`
    );
    const roundtrip = coreRoundtrip(created.value);
    check(
      roundtrip.ok && same(roundtrip.value, created.value),
      'Core and scure map-shape PSBT bytes differ after a no-op relay',
      `v${psbtVersion} ${inputs}/${outputs}: ${error(roundtrip)}`,
      'fingerprint',
      'Semantically equivalent serialized output'
    );
  }
}

console.log('== Bitcoin Core serialized decoder vectors ==');
const vectors = JSON.parse(readFileSync(CORE_VECTORS, 'utf8')) as {
  valid: string[];
  invalid: string[];
};
const validVectorFailures: string[] = [];
const validVectorFingerprints: string[] = [];
for (let i = 0; i < vectors.valid.length; i++) {
  const bytes = base64.decode(vectors.valid[i]);
  const coreResult = coreRoundtrip(bytes);
  const workResult = relay(bytes, () => {}, {
    allowUnknown: true,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
    proprietary: 'ignore',
  });
  const coreInfo = coreResult.ok ? coreInspect(coreResult.value) : coreResult;
  const workInfo = workResult.ok ? coreInspect(workResult.value) : workResult;
  if (
    !coreResult.ok ||
    !workResult.ok ||
    !coreInfo.ok ||
    !workInfo.ok ||
    JSON.stringify(coreInfo.value) !== JSON.stringify(workInfo.value)
  )
    validVectorFailures.push(`valid[${i}]: Core=${error(coreResult)}, scure=${error(workResult)}`);
  else if (!same(coreResult.value, workResult.value)) validVectorFingerprints.push(`valid[${i}]`);
}
check(
  validVectorFailures.length === 0,
  'scure rejects Bitcoin Core valid serialized PSBT vectors',
  validVectorFailures.slice(0, 8).join('; '),
  'candidate',
  'Observed Core valid-vector acceptance'
);
check(
  validVectorFingerprints.length === 0,
  'Core and scure canonicalize valid Core vectors to different PSBT bytes',
  validVectorFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);
const invalidVectorFailures: string[] = [];
for (let i = 0; i < vectors.invalid.length; i++) {
  const coreResult = run('roundtrip', vectors.invalid[i]);
  const decoded = attempt(() => base64.decode(vectors.invalid[i]));
  // Core's decoder also validates prevout semantics. Compare that with scure's public parser,
  // not RawPSBT: the raw codec intentionally validates only the serialized map structure.
  const workResult = decoded.ok
    ? attempt(() =>
        parse(decoded.value, {
          allowUnknown: true,
          allowUnknownInputs: true,
          allowUnknownOutputs: true,
          proprietary: 'ignore',
        })
      )
    : decoded;
  if (coreResult.ok || workResult.ok)
    invalidVectorFailures.push(`invalid[${i}]: Core=${coreResult.ok}, scure=${workResult.ok}`);
}
check(
  invalidVectorFailures.length === 0,
  'Core and scure disagree on invalid serialized PSBT vectors',
  invalidVectorFailures.slice(0, 8).join('; '),
  'candidate',
  'Observed Core invalid-vector rejection'
);

console.log('== ordinary ECDSA signing and finalization relay ==');
const sighashes = [
  btc.SigHash.ALL,
  btc.SigHash.NONE,
  btc.SigHash.SINGLE,
  btc.SigHash.ALL_ANYONECANPAY,
  btc.SigHash.NONE_ANYONECANPAY,
  btc.SigHash.SINGLE_ANYONECANPAY,
];
let signingFailures = 0;
const signingFingerprints: string[] = [];
for (const psbtVersion of [0, 2] as const) {
  for (const sighash of sighashes) {
    const bytes = simple(psbtVersion, sighash);
    const coreSigned = coreSign(bytes);
    const workFinal = coreSigned.ok ? finalizedByWork(coreSigned.value) : coreSigned;
    const coreFinal = coreSigned.ok ? coreFinalize(coreSigned.value) : coreSigned;
    const coreFromWork = workFinal.ok ? coreExtract(workFinal.value) : workFinal;
    const workFromWork = workFinal.ok ? extractedByWork(workFinal.value) : workFinal;
    if (!coreFromWork.ok || !workFromWork.ok || !same(coreFromWork.value, workFromWork.value))
      signingFailures++;
    if (coreFinal.ok && workFinal.ok && !same(coreFinal.value, workFinal.value))
      signingFingerprints.push(
        `v${psbtVersion} sighash=${sighash} finalizer: ` +
          `Core flags=${psbtVersion === 2 ? String(flags(coreFinal.value)) : '-'}, ` +
          `scure flags=${psbtVersion === 2 ? String(flags(workFinal.value)) : '-'}`
      );

    const workSigned = relay(bytes, (tx) => tx.signIdx(priv, 0, [sighash]));
    if (coreSigned.ok && workSigned.ok && !same(coreSigned.value, workSigned.value))
      signingFingerprints.push(
        `v${psbtVersion} sighash=${sighash} signer: ` +
          `Core flags=${psbtVersion === 2 ? String(flags(coreSigned.value)) : '-'}, ` +
          `scure flags=${psbtVersion === 2 ? String(flags(workSigned.value)) : '-'}`
      );
    const finalizedWork = workSigned.ok ? coreFinalize(workSigned.value) : workSigned;
    const workFinalFromWork = workSigned.ok ? finalizedByWork(workSigned.value) : workSigned;
    if (
      finalizedWork.ok &&
      workFinalFromWork.ok &&
      !same(finalizedWork.value, workFinalFromWork.value)
    )
      signingFingerprints.push(
        `v${psbtVersion} sighash=${sighash} work-signed finalizer: ` +
          `Core flags=${psbtVersion === 2 ? String(flags(finalizedWork.value)) : '-'}, ` +
          `scure flags=${psbtVersion === 2 ? String(flags(workFinalFromWork.value)) : '-'}`
      );
    const coreExtracted = finalizedWork.ok ? coreExtract(finalizedWork.value) : finalizedWork;
    const workExtracted = finalizedWork.ok ? extractedByWork(finalizedWork.value) : finalizedWork;
    if (!coreExtracted.ok || !workExtracted.ok || !same(coreExtracted.value, workExtracted.value))
      signingFailures++;
  }
}
check(
  signingFailures === 0,
  'ordinary signatures cannot alternate between Core and scure',
  `${signingFailures}/24 signer/finalizer directions failed`,
  'candidate',
  'BIP174 Signer and Finalizer; BIP143'
);
check(
  signingFingerprints.length === 0,
  'Core and scure ECDSA signing/finalization produce different PSBT bytes',
  signingFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

console.log('== Taproot key-path and script-path relay ==');
const taproot = (psbtVersion: 0 | 2, scriptPath: boolean, sighash?: number): Uint8Array => {
  const tapKey = utils.pubSchnorr(priv);
  const payment = scriptPath ? btc.p2tr(undefined, btc.p2tr_pk(tapKey)) : btc.p2tr(tapKey);
  const tx = new btc.Transaction({ PSBTVersion: psbtVersion });
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
const taprootFingerprints: string[] = [];
for (const psbtVersion of [0, 2] as const) {
  for (const scriptPath of [false, true]) {
    const bytes = taproot(psbtVersion, scriptPath);
    const roundtrip = coreRoundtrip(bytes);
    if (roundtrip.ok && !same(roundtrip.value, bytes))
      taprootFingerprints.push(`v${psbtVersion} scriptPath=${scriptPath} unsigned relay`);
  }
}
let taprootFailures = 0;
let coreTaprootCleanupFailures = 0;
const taprootSighashes = [undefined, ...sighashes];
for (const psbtVersion of [0, 2] as const) {
  for (const scriptPath of [false, true]) {
    for (const sighash of taprootSighashes) {
      const bytes = taproot(psbtVersion, scriptPath, sighash);
      const coreSigned = coreSign(bytes);
      const workFinal = coreSigned.ok ? finalizedByWork(coreSigned.value) : coreSigned;
      const coreFinalByCore = coreSigned.ok ? coreFinalize(coreSigned.value) : coreSigned;
      if (coreFinalByCore.ok && workFinal.ok && !same(coreFinalByCore.value, workFinal.value))
        taprootFingerprints.push(
          `v${psbtVersion} scriptPath=${scriptPath} sighash=${String(sighash)} finalizer`
        );
      const coreFromWork = workFinal.ok ? coreExtract(workFinal.value) : workFinal;
      const workFromWork = workFinal.ok ? extractedByWork(workFinal.value) : workFinal;
      if (!coreFromWork.ok || !workFromWork.ok || !same(coreFromWork.value, workFromWork.value))
        taprootFailures++;

      const workSigned = relay(bytes, (tx) =>
        tx.signIdx(priv, 0, sighash === undefined ? undefined : [sighash], new Uint8Array(32))
      );
      if (coreSigned.ok && workSigned.ok && !same(coreSigned.value, workSigned.value))
        taprootFingerprints.push(
          `v${psbtVersion} scriptPath=${scriptPath} sighash=${String(sighash)} signer`
        );
      const coreFinal = workSigned.ok ? coreFinalize(workSigned.value) : workSigned;
      const workFinalFromWork = workSigned.ok ? finalizedByWork(workSigned.value) : workSigned;
      if (coreFinal.ok && workFinalFromWork.ok && !same(coreFinal.value, workFinalFromWork.value))
        taprootFingerprints.push(
          `v${psbtVersion} scriptPath=${scriptPath} sighash=${String(sighash)} ` +
            'work-signed finalizer'
        );
      const coreExtracted = coreFinal.ok ? coreExtract(coreFinal.value) : coreFinal;
      const workExtracted = coreFinal.ok ? extractedByWork(coreFinal.value) : coreFinal;
      if (!coreExtracted.ok || !workExtracted.ok || !same(coreExtracted.value, workExtracted.value))
        taprootFailures++;
      if (coreFinal.ok && transientTaprootFields(coreFinal.value).length)
        coreTaprootCleanupFailures++;
    }
  }
}
check(
  taprootFailures === 0,
  'Taproot signatures cannot alternate between Core and scure',
  `${taprootFailures}/56 signer/finalizer directions failed`,
  'candidate',
  'BIP371; BIP341'
);
check(
  coreTaprootCleanupFailures === 0,
  'Core finalization retains transient Taproot input fields',
  `${coreTaprootCleanupFailures}/28 Core-finalized inputs retain BIP371 fields`,
  'candidate',
  'BIP371 PSBT_IN_TAP_KEY_SIG through PSBT_IN_TAP_MERKLE_ROOT'
);
check(
  taprootFingerprints.length === 0,
  'Core and scure Taproot relays/finalizers produce different PSBT bytes',
  taprootFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

console.log('== transaction-modifiable policy consumption ==');
const mutableV2 = simple(2);
const policyRoundtripFailures: string[] = [];
const futurePolicyRoundtripFailures: string[] = [];
for (const policy of [undefined, 0, 3, 255]) {
  const raw = rawV2(mutableV2);
  if (policy === undefined) delete raw.global.txModifiable;
  else raw.global.txModifiable = policy;
  const bytes = psbt.RawPSBTV2.encode(raw);
  const coreResult = coreRoundtrip(bytes);
  const workResult = attempt(() => parse(bytes).toPSBT(2));
  // Unassigned tx-modifiable bits follow the configured unknown-field policy. Default stripping
  // is intentional and distinguishable from a relay failure for the three assigned bits.
  const failures = policy === 255 ? futurePolicyRoundtripFailures : policyRoundtripFailures;
  if (!coreResult.ok || !same(coreResult.value, bytes))
    failures.push(`Core policy=${String(policy)}: ${error(coreResult)}`);
  if (!workResult.ok || !same(workResult.value, bytes))
    failures.push(`scure policy=${String(policy)}: ${error(workResult)}`);
}
check(
  policyRoundtripFailures.length === 0,
  'Core and scure rewrite transaction-modifiable presence during no-op relay',
  policyRoundtripFailures.join('; '),
  'candidate',
  'PSBTv2 serialized relay'
);
check(
  futurePolicyRoundtripFailures.length === 0,
  'scure strips unassigned transaction-modifiable bits during a default no-op relay',
  futurePolicyRoundtripFailures.join('; '),
  'intentional',
  'Configured unknown-field policy; use unknown=ignore for exact relay'
);
const mutationFingerprints: string[] = [];
for (let policy = 0; policy < 8; policy++) {
  const raw = rawV2(mutableV2);
  raw.global.txModifiable = policy;
  const bytes = psbt.RawPSBTV2.encode(raw);
  for (const [bit, name, coreAction, workAction] of [
    [
      1,
      'input',
      (value: Uint8Array) => coreAddInput(value, 40),
      (value: Uint8Array) => relay(value, workAddInput),
    ],
    [2, 'output', coreAddOutput, (value: Uint8Array) => relay(value, workAddOutput)],
  ] as const) {
    const expected = !!(policy & bit);
    const coreResult = coreAction(bytes);
    const workResult = workAction(bytes);
    check(
      coreResult.ok === expected && workResult.ok === expected,
      'Core and scure disagree on an explicit transaction-modifiable policy',
      `policy=${policy}, ${name}: expected=${expected}, Core=${error(coreResult)}, ` +
        `scure=${error(workResult)}`,
      'candidate',
      'BIP370 PSBT_GLOBAL_TX_MODIFIABLE'
    );
    if (coreResult.ok && workResult.ok && !same(coreResult.value, workResult.value))
      mutationFingerprints.push(`policy=${policy}, ${name}`);
  }
}
check(
  mutationFingerprints.length === 0,
  'Core and scure unsigned mutation produces different PSBT bytes',
  mutationFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

console.log('== transaction-modifiable combination ==');
let combineFlagFailures = 0;
const combineFingerprints: string[] = [];
for (let a = 0; a < 8; a++) {
  for (let b = 0; b < 8; b++) {
    const left = rawV2(mutableV2);
    const right = rawV2(mutableV2);
    left.global.txModifiable = a;
    right.global.txModifiable = b;
    const leftBytes = psbt.RawPSBTV2.encode(left);
    const rightBytes = psbt.RawPSBTV2.encode(right);
    const expected = (a & b & 3) | ((a | b) & 4);
    const coreResult = coreCombine(leftBytes, rightBytes);
    const workResult = attempt(() => btc.PSBTCombine([leftBytes, rightBytes]));
    if (
      !coreResult.ok ||
      flags(coreResult.value) !== expected ||
      !workResult.ok ||
      flags(workResult.value) !== expected
    )
      combineFlagFailures++;
    else if (!same(coreResult.value, workResult.value)) combineFingerprints.push(`flags ${a}/${b}`);
  }
}
check(
  combineFlagFailures === 0,
  'Core and scure combine transaction-modifiable flags differently',
  `${combineFlagFailures}/64 flag pairs differ`,
  'candidate',
  'BIP370 Combiner and PSBT_GLOBAL_TX_MODIFIABLE'
);
check(
  combineFingerprints.length === 0,
  'Core and scure transaction-modifiable combination produces different PSBT bytes',
  combineFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);
const omitted = rawV2(mutableV2);
delete omitted.global.txModifiable;
const omittedBytes = psbt.RawPSBTV2.encode(omitted);
const coreOmitted = coreCombine(omittedBytes, omittedBytes);
const workOmitted = attempt(() => btc.PSBTCombine([omittedBytes, omittedBytes]));
check(
  coreOmitted.ok &&
    workOmitted.ok &&
    flags(coreOmitted.value) === undefined &&
    flags(workOmitted.value) === undefined,
  'combining strict field-less PSBTv2 materializes a policy field',
  `Core=${coreOmitted.ok ? flags(coreOmitted.value) : coreOmitted.error}, ` +
    `scure=${workOmitted.ok ? flags(workOmitted.value) : workOmitted.error}`,
  'candidate',
  'BIP370 Combiner and PSBT_GLOBAL_TX_MODIFIABLE'
);
check(
  coreOmitted.ok && workOmitted.ok && same(coreOmitted.value, workOmitted.value),
  'Core and scure field-less combination produces different PSBT bytes',
  `Core=${error(coreOmitted)}, scure=${error(workOmitted)}`,
  'fingerprint',
  'Semantically equivalent serialized output'
);
const conflictAll = coreSign(simple(2, btc.SigHash.ALL));
const conflictNone = coreSign(simple(2, btc.SigHash.NONE));
if (conflictAll.ok && conflictNone.ok) {
  const coreConflict = coreCombine(conflictAll.value, conflictNone.value);
  const returned = coreConflict.ok ? relay(coreConflict.value, () => {}) : coreConflict;
  check(
    coreConflict.ok && returned.ok,
    'scure cannot consume Core conflict-resolved combination output',
    `Core combine=${error(coreConflict)}, Core result returned to scure=${error(returned)}`,
    'candidate',
    'Serialized Core -> scure handoff'
  );
}

console.log('== Core-produced signing-state relay ==');
let finalizedRelayFailures = 0;
const finalizedRelayFingerprints: string[] = [];
let finalizedRelayIndex = 0;
for (const bytes of [
  ...sighashes.map((sighash) => simple(2, sighash)),
  ...[undefined, ...sighashes].map((sighash) => taproot(2, false, sighash)),
]) {
  const fixture = finalizedRelayIndex++;
  const signed = coreSign(bytes);
  const finalized = signed.ok ? coreFinalize(signed.value) : signed;
  const relayed = finalized.ok ? relay(finalized.value, () => {}) : finalized;
  const coreTx = relayed.ok ? coreExtract(relayed.value) : relayed;
  const workTx = relayed.ok ? extractedByWork(relayed.value) : relayed;
  if (!coreTx.ok || !workTx.ok || !same(coreTx.value, workTx.value)) finalizedRelayFailures++;
  if (finalized.ok && relayed.ok && !same(finalized.value, relayed.value))
    finalizedRelayFingerprints.push(`v${version(bytes)} fixture=${fixture}`);
}
check(
  finalizedRelayFailures === 0,
  'Core-finalized PSBTs cannot round-trip through scure and return to Core',
  `${finalizedRelayFailures}/13 finalized handoffs failed or changed extraction`,
  'candidate',
  'Serialized Core -> scure -> Core handoff'
);
check(
  finalizedRelayFingerprints.length === 0,
  'scure changes Core-finalized PSBT bytes during a no-op relay',
  finalizedRelayFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

console.log('== signed mutation scopes ==');
const partialMutationFingerprints: string[] = [];
for (const sighash of sighashes) {
  const signed = coreSign(simple(2, sighash));
  if (!signed.ok) continue;
  const coreInput = coreAddInput(signed.value, 50);
  const coreOutput = coreAddOutput(signed.value);
  const workInput = relay(signed.value, workAddInput);
  const workOutput = relay(signed.value, workAddOutput);
  for (const [name, coreResult, workResult] of [
    ['input', coreInput, workInput],
    ['output', coreOutput, workOutput],
  ] as const) {
    if (coreResult.ok && workResult.ok && !same(coreResult.value, workResult.value))
      partialMutationFingerprints.push(`sighash=${sighash}, ${name}`);
  }
}
check(
  partialMutationFingerprints.length === 0,
  'Core and scure allowed signed mutations produce different PSBT bytes',
  partialMutationFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

console.log('== PSBT version combination ==');
const v0 = simple(0);
const v2 = simple(2);
for (const pair of [
  [v0, v2],
  [v2, v0],
] as const) {
  const workResult = attempt(() => btc.PSBTCombine(pair));
  const coreResult = workResult.ok ? coreInspect(workResult.value) : workResult;
  check(
    workResult.ok && coreResult.ok,
    'Core cannot consume scure cross-version combination output',
    `order=${version(pair[0])}/${version(pair[1])}: scure=${error(workResult)}, ` +
      `Core handoff=${error(coreResult)}`,
    'candidate',
    'Serialized scure -> Core handoff'
  );
}

console.log('== locktime reconstruction and relay ==');
const lockShape = (fallbackLocktime: number, requirements: Requirement[]): Uint8Array => {
  const tx = new btc.Transaction({ PSBTVersion: 2, lockTime: fallbackLocktime });
  for (let i = 0; i < requirements.length; i++)
    tx.addInput({
      txid: new Uint8Array(32).fill(i + 60),
      index: 0,
      sequence: 0xfffffffe,
      witnessUtxo: { amount, script: btc.p2wpkh(pub).script },
      ...requirements[i],
    });
  tx.addOutput({ amount: amount - 1_000n, script: btc.p2wpkh(pub).script });
  return tx.toPSBT(2);
};

console.log('== equivalent PSBTv2 representation combination ==');
const combineEquivalent = (
  name: string,
  left: Uint8Array,
  right: Uint8Array,
  kind: Kind = 'candidate'
): void => {
  const expected = describe(left).unsignedTx;
  for (const pair of [
    [left, right],
    [right, left],
  ] as const) {
    const coreResult = coreCombine(...pair);
    const workResult = attempt(() => btc.PSBTCombine(pair));
    const coreDescription = coreResult.ok ? attempt(() => describe(coreResult.value)) : coreResult;
    const workDescription = workResult.ok ? attempt(() => describe(workResult.value)) : workResult;
    check(
      coreDescription.ok &&
        coreDescription.value.unsignedTx === expected &&
        workDescription.ok &&
        workDescription.value.unsignedTx === expected,
      name,
      `order=${same(pair[0], left) ? 'left/right' : 'right/left'}: ` +
        `Core=${error(coreDescription)}, scure=${error(workDescription)}`,
      kind,
      'BIP174 Combiner; BIP370 Determining Lock Time'
    );
    if (coreResult.ok && workResult.ok && !same(coreResult.value, workResult.value))
      addFinding(
        'fingerprint',
        'Semantically equivalent serialized output',
        'Core and scure equivalent-state combination produces different PSBT bytes',
        `${name}, order=${same(pair[0], left) ? 'left/right' : 'right/left'}`
      );
  }
};
const explicitSequence = rawV2(mutableV2);
explicitSequence.inputs[0].sequence = 0xffffffff;
combineEquivalent(
  'Core and scure disagree when combining omitted and explicit default sequence',
  mutableV2,
  psbt.RawPSBTV2.encode(explicitSequence)
);
const omittedFallback = rawV2(mutableV2);
delete omittedFallback.global.fallbackLocktime;
combineEquivalent(
  'Core and scure disagree when combining omitted and explicit zero fallback locktime',
  mutableV2,
  psbt.RawPSBTV2.encode(omittedFallback)
);
const fallbackOne = lockShape(1, [{ requiredHeightLocktime: 123 }]);
const fallbackTwo = rawV2(fallbackOne);
fallbackTwo.global.fallbackLocktime = 2;
combineEquivalent(
  'scure rejects Core-compatible PSBTv2s with irrelevant fallback disagreement',
  fallbackOne,
  psbt.RawPSBTV2.encode(fallbackTwo)
);

const futureFlag = rawV2(mutableV2);
futureFlag.global.txModifiable = 8;
const knownFlag = rawV2(mutableV2);
knownFlag.global.txModifiable = 0;
const coreFuture = coreCombine(psbt.RawPSBTV2.encode(futureFlag), psbt.RawPSBTV2.encode(knownFlag));
const returnedFuture = coreFuture.ok ? relay(coreFuture.value, () => {}) : coreFuture;
check(
  coreFuture.ok && returnedFuture.ok,
  'scure cannot consume Core combination output with undefined mutability flags',
  `Core combine=${error(coreFuture)}, scure handoff=${error(returnedFuture)}`,
  'candidate',
  'Serialized Core -> scure handoff'
);

const lockRelayFingerprints: string[] = [];
for (const [fallback, requirements, expected] of [
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
  const bytes = lockShape(fallback, [...requirements]);
  const info = coreInspect(bytes);
  const workLocktime = attempt(() => parse(bytes).lockTime);
  const coreRelay = coreRoundtrip(bytes);
  const workRelay = relay(bytes, () => {});
  check(
    info.ok &&
      workLocktime.ok &&
      info.value.computed_locktime === expected &&
      workLocktime.value === expected,
    'Core and scure reconstruct different PSBTv2 locktimes',
    `expected=${expected}, Core=${info.ok ? info.value.computed_locktime : info.error}, ` +
      `scure=${workLocktime.ok ? workLocktime.value : workLocktime.error}`,
    'candidate',
    'BIP370 Determining Lock Time'
  );
  if (coreRelay.ok && workRelay.ok && !same(coreRelay.value, workRelay.value))
    lockRelayFingerprints.push(`fallback=${fallback}, locktime=${expected}`);
}
check(
  lockRelayFingerprints.length === 0,
  'Core and scure locktime relays produce different PSBT bytes',
  lockRelayFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

const locked = lockShape(0, [{ requiredHeightLocktime: 123 }]);
const coreLocked = coreSign(locked);
const workLocked = relay(locked, (tx) => tx.signIdx(priv, 0));
for (const [name, signed] of [
  ['Core', coreLocked],
  ['scure', workLocked],
] as const) {
  const coreChanged = signed.ok
    ? coreAddInput(signed.value, 70, { requiredHeightLocktime: 124 })
    : signed;
  const workChanged = signed.ok
    ? relay(signed.value, (tx) => workAddInput(tx, { requiredHeightLocktime: 124 }))
    : signed;
  check(
    !coreChanged.ok && !workChanged.ok,
    'a signed PSBT accepts an input that changes its effective locktime',
    `${name} signer: Core=${error(coreChanged)}, scure=${error(workChanged)}`,
    'candidate',
    'BIP370 Determining Lock Time; BIP143'
  );
}

let lockFinalFailures = 0;
for (const signer of ['Core', 'scure'] as const) {
  const signed = signer === 'Core' ? coreSign(locked) : relay(locked, (tx) => tx.signIdx(priv, 0));
  if (!signed.ok) {
    lockFinalFailures++;
    continue;
  }
  for (const finalizer of ['Core', 'scure'] as const) {
    const finalized =
      finalizer === 'Core' ? coreFinalize(signed.value) : finalizedByWork(signed.value);
    const info = finalized.ok ? coreInspect(finalized.value) : finalized;
    const workLocktime = finalized.ok ? attempt(() => parse(finalized.value).lockTime) : finalized;
    if (
      !info.ok ||
      info.value.computed_locktime !== 123 ||
      !workLocktime.ok ||
      workLocktime.value !== 123
    )
      lockFinalFailures++;
  }
}
check(
  lockFinalFailures === 0,
  'alternating finalizers lose a signature-committed PSBTv2 locktime',
  `${lockFinalFailures}/4 signer/finalizer paths lost locktime 123`,
  'candidate',
  'BIP370 Determining Lock Time; BIP143'
);
const lockFinalFingerprints: string[] = [];
for (const [signer, signed] of [
  ['Core', coreLocked],
  ['scure', workLocked],
] as const) {
  if (!signed.ok) continue;
  const coreFinal = coreFinalize(signed.value);
  const workFinal = finalizedByWork(signed.value);
  if (coreFinal.ok && workFinal.ok && !same(coreFinal.value, workFinal.value))
    lockFinalFingerprints.push(`${signer} signer`);
}
check(
  lockFinalFingerprints.length === 0,
  'Core and scure locktime finalization produces different PSBT bytes',
  lockFinalFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

const incompatibleRaw = rawV2(
  lockShape(0, [
    { requiredHeightLocktime: 123, requiredTimeLocktime: 600_000_000 },
    { requiredHeightLocktime: 124, requiredTimeLocktime: 700_000_000 },
  ])
);
delete incompatibleRaw.inputs[0].requiredTimeLocktime;
delete incompatibleRaw.inputs[1].requiredHeightLocktime;
const incompatible = psbt.RawPSBTV2.encode(incompatibleRaw);
const coreIncompatible = coreInspect(incompatible);
const workIncompatible = attempt(() => parse(incompatible));
check(
  coreIncompatible.ok && coreIncompatible.value.computed_locktime !== null && workIncompatible.ok,
  'scure rejects a Core-relayable PSBTv2 with incompatible locktime domains',
  `Core=${
    coreIncompatible.ok ? String(coreIncompatible.value.computed_locktime) : coreIncompatible.error
  }, scure=${error(workIncompatible)}`,
  'intentional',
  'Observed Core-to-scure locktime handoff'
);

console.log('== finalized and partial combination ==');
const partial = relay(v2, (tx) => tx.signIdx(priv, 0));
if (!partial.ok) throw new Error(partial.error);
const final = finalizedByWork(partial.value);
if (!final.ok) throw new Error(final.error);
for (const pair of [
  [partial.value, final.value],
  [final.value, partial.value],
] as const) {
  const coreCombined = coreCombine(...pair);
  const coreClean = coreCombined.ok ? coreFinalize(coreCombined.value) : coreCombined;
  const workCombined = attempt(() => btc.PSBTCombine(pair));
  for (const [name, result] of [
    ['Core', coreClean],
    ['scure', workCombined],
  ] as const) {
    const info = result.ok ? coreInspect(result.value) : result;
    check(
      info.ok &&
        info.value.final_inputs === 1 &&
        info.value.partial_signatures === 0 &&
        info.value.unsigned_tx === describe(v2).unsignedTx,
      'finalized/partial combination does not converge to clean finalized state',
      `${name}, order=${same(pair[0], partial.value) ? 'partial/final' : 'final/partial'}: ` +
        `${error(info)}`,
      'candidate',
      'BIP174 Combiner and Input Finalizer'
    );
  }
  if (coreClean.ok && workCombined.ok && !same(coreClean.value, workCombined.value))
    addFinding(
      'fingerprint',
      'Semantically equivalent serialized output',
      'Core and scure finalized/partial combination produces different PSBT bytes',
      `order=${same(pair[0], partial.value) ? 'partial/final' : 'final/partial'}`
    );
}

console.log('== opaque metadata relay ==');
const opaque = rawV2(mutableV2);
const unknown = [[{ type: 0xfd, key: Uint8Array.of(1) }, Uint8Array.of(2)]] as const;
// Proprietary key data is <compact identifier length><identifier><compact subtype>.
const proprietary = [[Uint8Array.of(1, 3, 4), Uint8Array.of(5)]] as const;
opaque.global.unknown = unknown as never;
opaque.inputs[0].unknown = unknown as never;
opaque.outputs[0].unknown = unknown as never;
opaque.global.proprietary = proprietary as never;
opaque.inputs[0].proprietary = proprietary as never;
opaque.outputs[0].proprietary = proprietary as never;
const opaqueBytes = psbt.RawPSBTV2.encode(opaque);
const coreOpaque = coreRoundtrip(opaqueBytes);
const opaqueCounts =
  coreOpaque.ok &&
  (() => {
    const raw = rawV2(coreOpaque.value);
    return {
      unknown:
        (raw.global.unknown?.length || 0) +
        (raw.inputs[0].unknown?.length || 0) +
        (raw.outputs[0].unknown?.length || 0),
      proprietary:
        (raw.global.proprietary?.length || 0) +
        (raw.inputs[0].proprietary?.length || 0) +
        (raw.outputs[0].proprietary?.length || 0),
    };
  })();
check(
  !!opaqueCounts && opaqueCounts.unknown === 3 && opaqueCounts.proprietary === 3,
  'Core loses opaque PSBT records during a no-op relay',
  opaqueCounts ? JSON.stringify(opaqueCounts) : error(coreOpaque),
  'candidate',
  'BIP174 Extensibility and Proprietary Use Type'
);
for (const [name, opts, expectedUnknown, expectedProprietary] of [
  ['default', {}, 0, 3],
  ['allowUnknown', { allowUnknown: true }, 3, 3],
  ['proprietaryIgnore', { proprietary: 'ignore' }, 0, 3],
] as const) {
  const workOpaque = coreOpaque.ok ? relay(coreOpaque.value, () => {}, opts) : coreOpaque;
  const counts =
    workOpaque.ok &&
    (() => {
      const raw = rawV2(workOpaque.value);
      return {
        unknown:
          (raw.global.unknown?.length || 0) +
          (raw.inputs[0].unknown?.length || 0) +
          (raw.outputs[0].unknown?.length || 0),
        proprietary:
          (raw.global.proprietary?.length || 0) +
          (raw.inputs[0].proprietary?.length || 0) +
          (raw.outputs[0].proprietary?.length || 0),
      };
    })();
  check(
    !!counts && counts.unknown === expectedUnknown && counts.proprietary === expectedProprietary,
    'scure opaque-field options change after a Core relay',
    `${name}: ${counts ? JSON.stringify(counts) : error(workOpaque)}`,
    name === 'default' ? 'intentional' : 'candidate',
    'BIP174 Extensibility and Proprietary Use Type'
  );
  if (counts && name === 'default' && counts.unknown !== opaqueCounts.unknown)
    addFinding(
      'intentional',
      'Core -> scure -> Core metadata handoff',
      'scure default relay removes Core-produced unknown metadata',
      `Core unknown=${opaqueCounts.unknown}, scure unknown=${counts.unknown}; ` +
        'allowUnknown preserves it'
    );
  if (workOpaque.ok && name === 'allowUnknown' && !same(workOpaque.value, coreOpaque.value))
    addFinding(
      'fingerprint',
      'Semantically equivalent serialized output',
      'scure opaque-field relay changes canonical Core PSBT bytes',
      `${name}: ${coreOpaque.value.length}/${workOpaque.value.length} bytes`
    );
}

console.log('== proprietary finalized-input cleanup ==');
const proprietaryRaw = rawV2(mutableV2);
proprietaryRaw.inputs[0].proprietary = proprietary as never;
const proprietaryBytes = psbt.RawPSBTV2.encode(proprietaryRaw);
const proprietarySigned = coreSign(proprietaryBytes);
const proprietaryCoreFinal = proprietarySigned.ok
  ? coreFinalize(proprietarySigned.value)
  : proprietarySigned;
for (const [name, opts, expected] of [
  ['default', {}, 0],
  ['proprietaryIgnore', { proprietary: 'ignore' }, 1],
] as const) {
  const finalized = proprietarySigned.ok
    ? relay(proprietarySigned.value, (tx) => tx.finalizeIdx(0), opts)
    : proprietarySigned;
  const count = finalized.ok ? rawV2(finalized.value).inputs[0].proprietary?.length || 0 : -1;
  check(
    count === expected,
    'scure proprietary cleanup option changes after Core signing',
    `${name}: expected=${expected}, got=${finalized.ok ? count : finalized.error}`,
    'candidate',
    'BIP174 Input Finalizer; Proprietary Use Type'
  );
  if (finalized.ok && proprietaryCoreFinal.ok) {
    if (name === 'default' && count !== 1)
      addFinding(
        'intentional',
        'Core -> scure -> Core metadata handoff',
        'scure default finalization removes Core-produced proprietary metadata',
        `Core proprietary=1, scure proprietary=${count}; proprietary=ignore preserves it`
      );
    if (name === 'proprietaryIgnore' && !same(finalized.value, proprietaryCoreFinal.value))
      addFinding(
        'fingerprint',
        'Semantically equivalent serialized output',
        'scure and Core finalization retain proprietary metadata with different PSBT bytes',
        `${proprietaryCoreFinal.value.length}/${finalized.value.length} bytes`
      );
  }
}

console.log('== exact non-minimal script commitments ==');
const funding = (script: Uint8Array): Uint8Array =>
  btc.RawTx.encode({
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
type Payment = {
  script: Uint8Array;
  redeemScript?: Uint8Array;
  witnessScript?: Uint8Array;
};
const paymentPSBT = (payment: Payment, psbtVersion: 0 | 2): Uint8Array => {
  const prev = funding(payment.script);
  const tx = new btc.Transaction({ PSBTVersion: psbtVersion });
  tx.addInput({
    txid: Uint8Array.from(utils.sha256x2(prev)).reverse(),
    index: 0,
    nonWitnessUtxo: prev,
    redeemScript: payment.redeemScript,
    witnessScript: payment.witnessScript,
  });
  tx.addOutput({ amount: amount - 1_000n, script: btc.p2wpkh(pub).script });
  return tx.toPSBT(psbtVersion);
};
const wrapperFingerprints: string[] = [];
const compareFinalizers = (
  name: string,
  bytes: Uint8Array,
  coreKeys = [privHex],
  workKeys = [priv]
): boolean => {
  let valid = true;
  for (const signer of ['Core', 'scure'] as const) {
    const signed =
      signer === 'Core'
        ? coreSign(bytes, coreKeys)
        : relay(bytes, (tx) => {
            for (const key of workKeys) tx.signIdx(key, 0);
          });
    const coreFinal = signed.ok ? coreFinalize(signed.value) : signed;
    const workFinal = signed.ok ? finalizedByWork(signed.value) : signed;
    const coreTx = coreFinal.ok ? coreExtract(coreFinal.value) : coreFinal;
    const workTx = workFinal.ok ? coreExtract(workFinal.value) : workFinal;
    if (!coreTx.ok || !workTx.ok || !same(coreTx.value, workTx.value)) {
      valid = false;
      addFinding(
        'candidate',
        'BIP174 Signer and Finalizer; BIP143',
        'canonical script wrappers cannot cross signer/finalizer implementations',
        `${name}, ${signer} signer: Core=${error(coreTx)}, scure=${error(workTx)}`
      );
    }
    if (coreFinal.ok && workFinal.ok && !same(coreFinal.value, workFinal.value))
      wrapperFingerprints.push(`${name}, ${signer} signer`);
  }
  return valid;
};

console.log('== canonical script-wrapper relay ==');
let wrapperFailures = 0;
let wrapperShapes = 0;
const canonicalPayments: [string, Payment][] = [
  ['p2pk', btc.p2pk(pub)],
  ['p2pkh', btc.p2pkh(pub)],
  ['p2sh-p2pk', btc.p2sh(btc.p2pk(pub))],
  ['p2wsh-p2pk', btc.p2wsh(btc.p2pk(pub))],
  ['p2sh-p2wsh-p2pk', btc.p2sh(btc.p2wsh(btc.p2pk(pub)))],
  ['p2sh-p2wpkh', btc.p2sh(btc.p2wpkh(pub))],
  ['p2wsh-p2pkh', btc.p2wsh(btc.p2pkh(pub))],
  ['p2sh-p2wsh-p2pkh', btc.p2sh(btc.p2wsh(btc.p2pkh(pub)))],
];
for (const psbtVersion of [0, 2] as const) {
  for (const [name, payment] of canonicalPayments) {
    const created = attempt(() => paymentPSBT(payment, psbtVersion));
    // Creator failures have no serialized interaction boundary and are outside this harness.
    if (!created.ok) continue;
    wrapperShapes++;
    if (!compareFinalizers(`${name} v${psbtVersion}`, created.value)) wrapperFailures++;
  }
}
const secondPriv = new Uint8Array(32).fill(8);
const multisig = btc.p2ms(2, [pub, utils.pubECDSA(secondPriv)]);
for (const psbtVersion of [0, 2] as const) {
  for (const [name, payment] of [
    ['p2sh-p2ms', btc.p2sh(multisig)],
    ['p2wsh-p2ms', btc.p2wsh(multisig)],
    ['p2sh-p2wsh-p2ms', btc.p2sh(btc.p2wsh(multisig))],
  ] as [string, Payment][]) {
    const created = attempt(() => paymentPSBT(payment, psbtVersion));
    if (!created.ok) continue;
    wrapperShapes++;
    if (
      !compareFinalizers(
        `${name} v${psbtVersion}`,
        created.value,
        [privHex, hex.encode(secondPriv)],
        [priv, secondPriv]
      )
    )
      wrapperFailures++;
  }
}
check(
  wrapperFailures === 0,
  'canonical script wrappers cannot cross signer/finalizer implementations',
  `${wrapperFailures}/${wrapperShapes} payment/version shapes failed`,
  'candidate',
  'BIP174 Signer and Finalizer; BIP143'
);
check(
  wrapperFingerprints.length === 0,
  'Core and scure canonical-wrapper finalization produces different PSBT bytes',
  wrapperFingerprints.join('; '),
  'fingerprint',
  'Semantically equivalent serialized output'
);

const legacy = (script: Uint8Array, outputs = 1, sighash = btc.SigHash.ALL): Uint8Array => {
  const prev = funding(script);
  const tx = new btc.Transaction({ PSBTVersion: 0 });
  tx.addInput({
    txid: Uint8Array.from(utils.sha256x2(prev)).reverse(),
    index: 0,
    nonWitnessUtxo: prev,
    sighashType: sighash,
  });
  for (let i = 0; i < outputs; i++)
    tx.addOutput({ amount: amount - 1_000n - BigInt(i), script: btc.p2wpkh(pub).script });
  return tx.toPSBT(0);
};
const rawPkh = Uint8Array.from([0x76, 0xa9, 0x4c, 0x14, ...utils.hash160(pub), 0x88, 0xac]);
const nonminimal = legacy(rawPkh);
for (const signer of ['Core', 'scure'] as const) {
  const signed =
    signer === 'Core' ? coreSign(nonminimal) : relay(nonminimal, (tx) => tx.signIdx(priv, 0));
  const coreFinal = signed.ok ? coreFinalize(signed.value) : signed;
  const coreTx = coreFinal.ok ? coreExtract(coreFinal.value) : coreFinal;
  const workFinal = signed.ok ? finalizedByWork(signed.value) : signed;
  const workTx = workFinal.ok ? coreExtract(workFinal.value) : workFinal;
  check(
    coreTx.ok && workTx.ok && same(coreTx.value, workTx.value),
    'Core cannot finalize a partial signature for a non-minimal committed script',
    `${signer} signer: Core finalizer=${error(coreTx)}, scure finalizer=${error(workTx)}`,
    'intentional',
    'Observed alternating signer/finalizer behavior for exact script bytes'
  );
}

console.log('== legacy SIGHASH_SINGLE hash-of-one ==');
const single = legacy(btc.p2pkh(pub).script, 0, btc.SigHash.SINGLE);
const coreSingle = coreSign(single);
const coreSingleValid =
  coreSingle.ok &&
  (() => {
    const signature = parse(coreSingle.value).getInput(0).partialSig?.[0][1];
    if (!signature) return false;
    const digest = parse(single).preimageLegacy(0, btc.p2pkh(pub).script, btc.SigHash.SINGLE);
    return secp256k1.verify(signature.subarray(0, -1), digest, pub, {
      format: 'der',
      lowS: false,
      prehash: false,
    });
  })();
check(
  !!coreSingleValid,
  'scure cannot verify Core legacy SIGHASH_SINGLE hash-of-one signatures',
  coreSingle.ok ? `valid=${coreSingleValid}` : coreSingle.error,
  'candidate',
  'Bitcoin consensus SIGHASH_SINGLE hash-of-one; BIP174 Signer'
);

console.log('== bip174js zero-output compatibility map ==');
const compat = attempt(() => {
  const tx = new btc.Transaction({ PSBTVersion: 0, bip174jsCompat: true });
  tx.addInput({
    txid: new Uint8Array(32).fill(80),
    index: 0,
    witnessUtxo: { amount, script: btc.p2wpkh(pub).script },
  });
  return tx.toPSBT(0);
});
const coreCompat = compat.ok ? coreInspect(compat.value) : compat;
check(
  coreCompat.ok,
  'Core rejects the opt-in bip174js zero-output compatibility map',
  error(coreCompat),
  'intentional',
  'Observed Core parser behavior for scure bip174js-compatible output'
);

console.log(`\n${checks} checks, ${findings.size} Core interoperability findings`);
for (const [name, finding] of findings) {
  console.log(`\n[${finding.kind.toUpperCase()}] ${name}`);
  console.log(`  Context: ${finding.context}`);
  for (const line of finding.evidence) console.log(`  - ${line}`);
}

export { findings };

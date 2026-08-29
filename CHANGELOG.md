# Changelog for scure-btc-signer

## 2.4.1 (2026-08-29)

- Upgrade micro-packed to 0.11.1

## 2.4.0 (2026-08-28)

Tons of hardening. Special thanks to Red Team (Rob Hamilton, CalleBTC, Omer Talip) for reports.

### Breaking changes

Breaking changes do not mean "locked funds", it's mostly "throws a new error".

- Unknown and proprietary PSBT fields supplied directly to `addInput`/`updateInput`/`addOutput`/`updateOutput` now throw under the default `strip` policy instead of being silently dropped; pass `unknown: 'ignore'` (and/or `proprietary: 'ignore'`) to preserve them
- `Transaction.combine` compares transaction `version` and effective `lockTime` (instead of raw constructor options) and throws on conflicting global fields it previously overwrote
- MuSig2 `partialSigAgg` with fewer signatures than participants now throws
- Taproot SIGHASH_SINGLE preimage for a missing output index now throws instead of returning a digest
- BIP370 locktime resolution now throws on inputs with incompatible height / time requirements (see below — the old behavior produced transactions which were not accepted by miners)

### New features

- New `TxOpts.unknown` and `TxOpts.proprietary` policies for unknown / proprietary PSBT fields
  (`proprietary` defaults to the `unknown` setting; `Unknowns` type is exported):
    - `'strict'`: throw when an unknown field is encountered during parsing
    - `'strip'` (default): accept & remove while parsing; throw when one is added / updated by the user
    - `'ignore'`: pass fields through from decode to encode (the spec's default behavior)
    - Why strip by default: opaque fields are a fingerprinting and data-exfiltration channel — a protocol
      can mark users with hidden fields, and a compromised cold wallet can leak secrets through data
      nobody inspects. Stripping guarantees no opaque data remains; known fields can still carry
      information, so inspecting all fields is still on the user
    - `allowUnknown` is deprecated: `true` maps to `'ignore'`, `false` to `'strip'`
- Fields from recent BIPs are now decoded explicitly and survive round-trips instead of being treated
  as unknown: MuSig2 / BIP373 (`musig2ParticipantPubkeys`, `musig2PubNonce`, `musig2PartialSig`),
  silent payments / BIP375-376 (`spEcdhShare`, `spDleq`, `spSpendBip32Derivation`, `spTweak`,
  `spV0Info`, `spV0Label`), BIP322 (`genericSignedMessage`), BIP353 (`dnssecProof`) and
  pay-to-contract / BIP372 (`p2cKeyTweak`)
- Full PSBTv2 (BIP370) `txModifiable` support:
    - Newly created PSBTv2 transactions set the field by default (inputs & outputs modifiable), and
      `addInput` / `updateInput` / `addOutput` / `updateOutput` enforce its bits, including the
      restrictions implied by existing signatures. Unknown `txModifiable` bits follow the `unknown` policy
    - Previously the field was never emitted, which hurt interoperability: to other libraries an
      absent field means "no inputs / outputs can be added"
    - New `TxOpts.allowMissingTxModifiable` (default `true`) still treats an absent field as
      modifiable, for PSBTs produced by older versions; set it to `false` for stricter validation
      when possible
    - Note: emitting the field changes the serialized output, so older library versions cannot
      convert newly produced PSBTv2 into PSBTv0
- BIP370 locktime handling (breaking, but the old behavior produced transactions which were not accepted by miners):
    - `requiredHeightLocktime` / `requiredTimeLocktime` are range-validated and now survive input
      finalization — previously they were deleted on finalize, so the extracted transaction's
      `lockTime` almost never matched what was signed
    - Effective `lockTime` resolution follows BIP370 exactly: height is preferred when supported by
      all inputs, and inputs with incompatible height / time requirements now throw instead of being
      silently accepted
- New `filterTaproot(inputs, pubkeys)` export and `selectUTXO` option `filterTaproot`: removes
  Taproot key / script paths not satisfiable by the supplied Schnorr keys before fee estimation and
  selection — no more manually stripping `tapInternalKey` / `tapLeafScript` to force a spending
  path. Without a filter, all keys present in inputs are still assumed accessible and the
  minimal-weight path is chosen
- New `TxOpts.strictPrevoutValidation`: requires every input to carry a full `nonWitnessUtxo` matching its outpoint before any signature is produced, preventing forged `witnessUtxo` amounts from understating the fee of untrusted / multi-party PSBTs
- New `taprootNumsKey()` returns an owned copy of the Taproot NUMS key; `TAPROOT_UNSPENDABLE_KEY` is deprecated (it is now a copy, so mutating it no longer affects library internals)
- `PSBTCombine(psbts, opts?)` now accepts transaction options; new `combineKeyMap` export in `psbt.js` for conflict-checked symmetric map union
- `p2sh` / `p2wsh` accept a new `allowNonCanonicalScript` parameter; `combinations` accepts `maxCombinations` and `MAX_COMBINATIONS` (4096) is exported
- `PSBTInputSignatureKeys` export replaces the deprecated `PSBTInputUnsignedKeys`

### Hardening

- `nonWitnessUtxo` txid and selected output are now validated during input normalization (`addInput`, `updateInput`, UTXO selection), not only at the PSBT decode boundary, so a mismatched previous transaction cannot understate a legacy input amount
- Taproot input commitments are verified against the previous output: `tapInternalKey`, `tapMerkleRoot` and every `tapLeafScript` control block must reproduce the P2TR output key (and parity); Taproot metadata on a non-P2TR prevout is rejected (skippable via `disableScriptCheck`)
- Signed-field protection is now sighash-aware: fields actually committed by existing signatures (outpoint, sequence, prevout data, scripts, `sighashType`) cannot be added, changed or removed; mutations that would change the effective `lockTime` of a signed transaction throw; finalized inputs only permit clearing/repeating already-present satisfaction fields
- `Transaction.combine` was rewritten: it validates the fully combined candidate before mutating the receiver, rejects conflicting global scalars instead of silently preferring one side, requires finalized inputs to agree on satisfaction shape, merges `txModifiable` with intersection/union semantics, and handles v0/v2 cross-version combination correctly. Combining a finalized input with a partially signed copy keeps the finalized result and drops the obsolete partial-signature data
- Signing with SIGHASH_SINGLE and no corresponding output now throws for Taproot inputs (BIP341 defines no such digest) instead of producing a consensus-invalid signature; the legacy pre-SegWit "SIGHASH_SINGLE bug" digest now matches Bitcoin Core's little-endian `uint256(1)` bytes — the previous big-endian encoding produced signatures the network rejects
- MuSig2 `Session.partialSigAgg` now requires exactly one partial signature per participant (previously any non-empty list); documentation on secret-nonce single-use added throughout
- Multisig duplicate-key detection (`p2ms`, `p2tr_ns`, `p2tr_ms`) validates keys and normalizes compressed/uncompressed SEC1 encodings, so one signer can no longer occupy multiple threshold slots by re-encoding a key
- `p2sh` / `p2wsh` reject non-minimal (non-canonical) redeem/witness scripts by default (`allowNonCanonicalScript` to override) — Core's MINIMALDATA policy means such transactions won't be relayed or added to the mempool, though they remain consensus-valid; scriptPubKeys and nested witness programs with non-canonical pushes no longer classify as SegWit outputs
- Proprietary (0xfc) PSBT keys must parse as a valid BIP174 identifier/subtype; PSBT decoding now requires the exact declared number of input maps (bip174js phantom-empty-map compatibility is narrowed to the specific zero-input v0 case)
- Resource bounds: Taproot script trees are limited to BIP341's depth of 128, `tr_ns`/`tr_ms` to 999 keys, and combination materialization (e.g. m-of-n `p2tr_ns` wallets) to `MAX_COMBINATIONS`
- Fee estimation and Taproot finalization now select the available leaf with the smallest complete witness (instead of the shallowest control block), skip unsatisfiable paths, and no longer abort when an unknown leaf appears before a satisfiable one. Estimated fees may change slightly (they are now more accurate); `tapLeafScript` is no longer sorted in place, so returned metadata retains its original ordering

### Bug fixes and behavior changes

- Importing UTXOs with non-minimal scripts now works: legacy/BIP143 signing and finalization retain the exact committed script bytes (including consensus-valid non-minimal pushes) instead of a re-encoded canonical form
- PSBTv2 output now always includes `fallbackLocktime` and `txModifiable`, matching Bitcoin Core's encoding and reducing library fingerprinting; PSBTv0 conversion strips v2-only fields after translating the unsigned transaction
- `bip174jsCompat` is now actually compatible with bip174js: only the single empty output map is emitted for zero-output PSBTv0 (a phantom input map cannot be represented in v0 framing)
- Estimator/`selectUTXO` options are normalized through the full `Transaction` option validation even with `createTx: false`, and adding an output at an index already covered by a SIGHASH_SINGLE signature is rejected
- Dependencies (`@noble/curves`, `@noble/hashes`, `@scure/base`, `micro-packed`) are now pinned to exact versions

## 2.3.0 (2026-08-08)

### New: net.js — Esplora / Electrum HTTP API

New optional submodule `@scure/btc-signer/net.js`. The core signer still has no network code — net.js must be imported explicitly and takes a caller-supplied fetch-compatible transport.

Esplora is different from most other btc full node setups because it allows to provide instalt account balance and history for any random address. So we provide block explorer-like methods.

- EsploraProvider: height, blockInfo, fee, balance, txCount, sendTx, waitForTx, txInfo, unspent, transfers, history, historyMulti
- history/historyMulti are async generators — rows stream newest-first while pages fetch; stopping early stops fetching. historyMulti de-duplicates by txid across addresses (HD wallets)
- Retry with exponential backoff on GETs (429/5xx, dropped connections); sendTx is never retried, so a lost response can't cause a re-broadcast
- Scans accept signal and onProgress; raw-tx fan-out bounded by concurrency (default 8)
- Fetched raw txs are verified against the requested txid; pagination is guarded against cursor loops
- New `README-fullnode.md`: bitcoind + Electrs/Esplora setup guide

### Hardening-related behavior changes

- payment: output matchers (pkh/sh/ms/tr/tr_ms) rejees — those now decode as unknown instead of throwing(wrong-length HASH160, invalid pubkeys, degenerate m/n, off-curve 32-byte v1 programs)
- payment: Address() handles BIP433 P2A; explicit Coe, decode no longer includes undefined
- payment: p2tr(...).tapLeafScript built directly — treat returned metadata as immutable
- Argument validation tightened across payment/psbt/2: consistent "name" expected X, got type=Y errors.

### Bug fixes

- transaction: allowUnknownVersion was inverted — it threw Unknown version for every numeric version, making the option unusable
- transaction: nonWitnessUtxo with a non-standard nVersion is now accepted (consensus doesn't restrict it; the tx is still spendable)
- utxo: selectUTXO all strategy returned a result on insufficient funds, reporting a negative fee; now returns undefined
- script: Script.encode treated inherited Object.prototype keys ('toString', 'constructor') as opcodes instead of failing
- script: OpToNum safe-integer bound is now symmetric — large negatives lost precision through Number()
- p2p: elligatorSwift.encode sampled u from 1..n-1 (secret-key sampler) instead of the full field as BIP324 requires; also now rejects off-curve x, which could emit an encoding decoding to a different pubkey
- p2p: bip324SharedSecret requires a real boolean for initiating
- musig2: BIP327 is_infinite(Q) check; aggNonce length validation; wrong k1 → wrong k2 message

### Misc

- Performance improvements for ElligatorSwift, Musig2, others
- No more bigint literals in source (engine compat)
- Reduce on-disk package size: 1019kb → 933kb (-86.2kb), by disabling source maps (they became less relevant).

## 2.2.0 (2026-04-28)

* **April 2026 self-audit** (all files): no major issues found
  * Audited for spec compliance and security
  * Improve robustness of `OP_CODESEPARATOR`: previously tx with would roundtrip via script/encode decode, which means we can verify OR consider correct tx which because of wrong preimage (number canonicalization/minimal encoding won't preserve exact bytes)
  * musig2: `partialSigVerify` was incorrectly returning `true` when a specific nonce was correct, but other pubnonces were broken / different from aggregated nonce
  * Hardened weight calculation for varint / mixed segwit + legacy
* Fix all Byte Array types, to ensure proper work in both TypeScript 5.6 & TypeScript 5.9+
  * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`
  * This creates incompatibility of code between versions
  * Previously, it was hard to use and constantly emitted errors similar to `TS2345`
  * See [[typescript#62240](https://github.com/microsoft/TypeScript/issues/62240)](https://github.com/microsoft/TypeScript/issues/62240) for more context
* Fix compilation issues on TypeScript v6
* Improve tree-shaking, reduce bundle sizes
* Upgrade all dependencies
* Add initial support for tapBip32Derivation
* PSBT merging now works with different versions
* Minor improvements by contributors
  * Fix typo in `_Estimator.getSatoshi` argument name by @anonpay-sh in https://github.com/paulmillr/scure-btc-signer/pull/130
  * Use stricter return type for `getAddress` utility by @anonpay-sh in https://github.com/paulmillr/scure-btc-signer/pull/129
  * fix typing for `pubSchnorr` to accept Uint8Array only by @imcotton in https://github.com/paulmillr/scure-btc-signer/pull/137
  * test(musig2): tighten BIP327 error assertions by @eminogrande in https://github.com/paulmillr/scure-btc-signer/pull/141

*(We're skipping v2.1, to align with other noble / scure packages)*

### New Contributors
* @anonpay-sh made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/130
* @eminogrande made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/132
* @imcotton made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/137

## 2.0.1 (2025-09-09)

- Disable extension-less imports. If you've used `/musig2`, switch to `/musig2.js` now. See [2.0.0](https://github.com/paulmillr/scure-btc-signer/releases/tag/2.0.0) for more details.
- pkg.json: add exports, for code editor autocompletion. Closes https://github.com/paulmillr/scure-btc-signer/issues/127

## 2.0.0 (2025-08-25)

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
    - Node v20.19 is now the minimum required version
    - Package imports now work correctly in bundler-less environments, such as browsers
    - Reduces npm package size (traffic consumed)
    - Reduces unpacked npm size (on-disk space)
- Upgrade to noble v2
- Upgrade typescript compilation env to ts5.9 and es2022
- Do not throw Transaction.id if not finalized by @louisinger in https://github.com/paulmillr/scure-btc-signer/pull/126

## 1.8.1 (2025-05-29)

* Export all modules with `.js` extension in addition to extension-less exports
* allowUnknownVersion flag for non-standard tx versions by @adambor in https://github.com/paulmillr/scure-btc-signer/pull/125
* fix: spending all required indices by @liquidleif in https://github.com/paulmillr/scure-btc-signer/pull/124

### New Contributors
* @adambor made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/125
* @liquidleif made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/124

## 1.8.0 (2025-04-24)

- Return hash in P2Ret for hash based payments. https://github.com/paulmillr/scure-btc-signer/issues/20
- Remove circular imports, make it friendlier to bad bundlers
- p2p: Add experimental support for ElligatorSwift from [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
- Bump hashes to [v1.8.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.8.0), curves to [v1.9.0](https://github.com/paulmillr/noble-curves/releases/tag/1.9.0), base to [1.2.5](https://github.com/paulmillr/scure-base/releases/tag/1.2.5), packed to [v0.7.3](https://github.com/paulmillr/micro-packed/releases/tag/0.7.3)
- Standalone build files are now attested in CI. Check out README for verification guide

## 1.7.0 (2025-03-01)

* Implement MuSig2 from BIP327
    * Special thanks to [Arklabs](https://arklabs.to) for funding the feature
* Support unknown psbt keypairs by @louisinger in https://github.com/paulmillr/scure-btc-signer/pull/119
* Fix gh-122: duplicate usage of requiredInputs
* Bump devdeps typescript to 5.8.2, jsbt to 0.3.2, prettier to 3.5.2

### New Contributors
* @louisinger made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/119

## 1.6.0 (2025-01-18)

* Add support for version 3 transactions by @mcbagz in https://github.com/paulmillr/scure-btc-signer/pull/116
* Support Pay to Anchor Output Types by @russeree in https://github.com/paulmillr/scure-btc-signer/pull/121
* Use typescript verbatimModuleSyntax to support future node.js type stripping
* Add some explicit types for typescript isolatedDeclarations and improved docs
* Publish to JSR.io

### New Contributors
* @mcbagz made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/116
* @russeree made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/121

## 1.5.0 (2024-11-23)

- Improve p2wpkh behavior when inputSighash is undefined
- Reuse bytes check from deps
- Bump hashes to [v1.6.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.6.0), curves to [v1.7.0](https://github.com/paulmillr/noble-curves/releases/tag/1.7.0), base to [1.2](https://github.com/paulmillr/scure-base/releases/tag/1.2.0), packed to [v0.7](https://github.com/paulmillr/micro-packed/releases/tag/0.7.0)

## 1.4.0 (2024-09-18)

### What's Changed
* Fix psbt parsing, support tap_bip32_derivation. gh-100, gh-101
* transaction, utxo: add getOutputAddress, allowSameUtxo, requiredInputs
* Fix dust relay fees (gh-107)
* feat: better error message for when type is not bigint by @dogebonker in https://github.com/paulmillr/scure-btc-signer/pull/99
* Allow exact match of target === input amount during accumulation. by @ph101pp in https://github.com/paulmillr/scure-btc-signer/pull/106
* Improve ESM compat
* Update dependencies

### New Contributors
* @dogebonker made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/98
* @ph101pp made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/106

## 1.3.2 (2024-05-17)

* Export back `taprootTweakPubkey`
* Bump dependency micro-packed with perf improvements and bugfixes

@omahs made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/89

## 1.3.1 (2024-04-19)

* utxo: allow passing customScripts into `tapLeafScript`
* multisig: allow passing network. Closes gh-79

## 1.3.0 (2024-04-17)

* Add support for custom scripts. That simplifies Ordinals / Inscriptions. We've made a separate package for them, that builds on top of btc-signer: https://github.com/paulmillr/micro-ordinals
* Regression: `getInputType` was not exported
* Split library into different files to simplify maintenance in https://github.com/paulmillr/scure-btc-signer/pull/80

## 1.2.2 (2024-03-24)

* Update noble-hashes [to v1.4.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.4.0)
* Update noble-curves [to v1.4.0](https://github.com/paulmillr/noble-curves/releases/tag/1.4.0)
* Build process improvements: now providing standalone file

## 1.2.1 (2024-01-12)

Adjust safety checks for cases where transactions are copying outputs into new inputs. Closes gh-66.

## 1.2.0 (2024-01-06)

* Implement UTXO selection: strategies of choosing which UTXOs to use as inputs when making an on-chain bitcoin payment
* Switch package to hybrid common.js-esm
* Make `Transaction#preimageWitness` methods public

## 1.1.1 (2023-12-12)

* Update deps
    * noble-hashes to [1.3.3](https://github.com/paulmillr/noble-hashes/releases/tag/1.3.3)
    * noble-curves to [1.3.0](https://github.com/paulmillr/noble-curves/releases/tag/1.3.0)
    * scure-base to [1.1.4](https://github.com/paulmillr/scure-base/releases/tag/1.1.4)
    * micro-packed to [0.4.0](https://github.com/paulmillr/micro-packed/releases/tag/0.4.0)
    * typescript to 5.3.2
* fix: PSBT Version overwritten in opts on clone by @victorkirov in https://github.com/paulmillr/scure-btc-signer/pull/64
* fix: Updating nonWitnessUtxo on input to undefined by @victorkirov in https://github.com/paulmillr/scure-btc-signer/pull/63

### New Contributors
* @victorkirov made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/64

## 1.1.0 (2023-09-03)

* Introduce improved `SigHash` instead of `SignatureHash` https://github.com/paulmillr/scure-btc-signer/pull/54
* Improve security: Throw an error on internalKey inside of p2tr leaf script
* Consistent use of "unknown" by @kyranjamie in https://github.com/paulmillr/scure-btc-signer/pull/52
    * `allowUnknowOutput` => `allowUnknownOutputs`
    * `allowUnknowInput` => `allowUnknownInputs`
* Improve security: Harden typescript compilation options
* Fix typo in errors by @kyranjamie in https://github.com/paulmillr/scure-btc-signer/pull/50
* Fix `validateOpts` in serverless environments
* Update noble-curves to 1.2 https://github.com/paulmillr/noble-curves/releases/1.2.0

### New Contributors
* @kyranjamie made their first contribution in https://github.com/paulmillr/scure-btc-signer/pull/50

## 1.0.1 (2023-06-19)

* fix: incorrect weight estimation for wph, wsh, and tr transactions #41 by @mahnunchik in https://github.com/paulmillr/scure-btc-signer/pull/42
* fix: validate address in addOutputAddress #37 by @mahnunchik in https://github.com/paulmillr/scure-btc-signer/pull/43

## 1.0.0 (2023-04-12)

First stable release. Upgrade to stable noble-curves.

## 0.1.0 (2022-09-02)

- Initial release

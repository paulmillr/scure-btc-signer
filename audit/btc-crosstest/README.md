# btc-crosstest

`btc-crosstest` is a daemon-free command-line bridge to Bitcoin Core's native PSBT
implementation. It exists for differential tests which pass serialized PSBTs between
implementations.

It does not start a node, use RPC, read Bitcoin configuration, create wallets, open a datadir, or
access chain state. The selected Core checkout is compiled as a library dependency.

## Build

The Core checkout must contain BIP370 support (merge commit `d7ed2840ac` or a descendant).

```console
cmake -S audit/btc-crosstest -B /path/to/btc-crosstest-build \
  -DBITCOIN_SOURCE_DIR=/path/to/bitcoin
cmake --build /path/to/btc-crosstest-build --target btc-crosstest
```

The binary is `/path/to/btc-crosstest-build/btc-crosstest`. Keep the build directory outside this
repository so Core's generated files do not become audit artifacts.

Run the comparison with the bridge and Core source paths supplied by the caller:

```console
BTC_CROSSTEST=/path/to/btc-crosstest-build/btc-crosstest \
BITCOIN_SOURCE_DIR=/path/to/bitcoin node audit/compare-core.ts
```

`BITCOIN_PSBT_VECTORS` may point directly to `rpc_psbt.json` instead of supplying
`BITCOIN_SOURCE_DIR`.

## Interface

Every successful command writes exactly one value followed by a newline. Errors go to stderr and
return status 1.

```text
btc-crosstest version
btc-crosstest inspect PSBT_BASE64
btc-crosstest roundtrip PSBT_BASE64
btc-crosstest combine PSBT_BASE64 PSBT_BASE64 [PSBT_BASE64 ...]
btc-crosstest finalize PSBT_BASE64
btc-crosstest extract PSBT_BASE64
btc-crosstest sign PSBT_BASE64 PRIVKEY_HEX [PRIVKEY_HEX ...]
btc-crosstest add-input PSBT_BASE64 TXID VOUT [SEQUENCE|-] [HEIGHT_LOCKTIME|-] [TIME_LOCKTIME|-]
btc-crosstest add-output PSBT_BASE64 AMOUNT_SAT SCRIPT_HEX
```

`roundtrip`, `combine`, `finalize`, `sign`, `add-input`, and `add-output` return a base64 PSBT.
`extract` returns a witness-serialized transaction in hex. `sign` adds partial signatures without
finalizing, allowing the finalizer to be tested independently.

`inspect` returns one compact JSON object describing Core's reconstructed transaction and relevant
PSBTv2 state. It is diagnostic only; serialized output remains the interoperability boundary.

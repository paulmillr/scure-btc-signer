#!/usr/bin/env python3
import json
import subprocess
import sys


if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} /path/to/btc-crosstest")

binary = sys.argv[1]
psbt = (
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQEfECcAAAAAAAAW"
    "ABSjxrHuSknZ8q87OAKXR0T7qSQWSgEOIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
    "AQEBAQEBAQ8EAAAAAAEQBP////8AAQMIKCMAAAAAAAABBBYAFKPGse5KSdnyrzs4ApdHRP"
    "upJBZKAA=="
)
unsigned = (
    "020000000101010101010101010101010101010101010101010101010101010101010101010000000000"
    "ffffffff012823000000000000160014a3c6b1ee4a49d9f2af3b3802974744fba924164a00000000"
)
summary = {
    "psbt_version": 2,
    "tx_version": 2,
    "fallback_locktime": 0,
    "tx_modifiable": 3,
    "computed_locktime": 0,
    "inputs": 1,
    "outputs": 1,
    "signature_inputs": 0,
    "final_inputs": 0,
    "partial_signatures": 0,
    "unsigned_tx": unsigned,
}


def run(*args, ok=True):
    result = subprocess.run([binary, *args], text=True, capture_output=True)
    expected_code = 0 if ok else 1
    assert (result.returncode, result.stderr if ok else result.stdout) == (expected_code, "")
    return result.stdout if ok else result.stderr


assert run("version") == "2\n"
assert json.loads(run("inspect", psbt)) == summary
assert run("roundtrip", psbt) == f"{psbt}\n"
assert run("combine", psbt, psbt) == f"{psbt}\n"
assert run("finalize", psbt) == f"{psbt}\n"
assert run("extract", psbt, ok=False) == "error: PSBT is incomplete\n"
assert run("roundtrip", "not-a-psbt", ok=False) == "error: invalid base64\n"

added_output = run("add-output", psbt, "1", "51").strip()
assert json.loads(run("inspect", added_output)) == {
    **summary,
    "outputs": 2,
    "unsigned_tx": unsigned.replace(
        "012823000000000000160014a3c6b1ee4a49d9f2af3b3802974744fba924164a00000000",
        "022823000000000000160014a3c6b1ee4a49d9f2af3b3802974744fba924164a"
        "0100000000000000015100000000",
    ),
}

added_input = run("add-input", psbt, "02" * 32, "1").strip()
assert json.loads(run("inspect", added_input)) == {
    **summary,
    "inputs": 2,
    "unsigned_tx": unsigned.replace(
        "01" + "01" * 32 + "0000000000ffffffff01",
        "02" + "01" * 32 + "0000000000ffffffff" + "02" * 32 + "0100000000ffffffff01",
    ),
}

signed = (
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQEfECcAAAAAAAAW"
    "ABSjxrHuSknZ8q87OAKXR0T7qSQWSiICApicC3bLVjlx/cm+8x7AbDVg8ySdbunl2DxX"
    "YlWW4F9vRzBEAiBsOfIJ6u5VynUMnqJEzuHga0AFDM8HGYwYLXshgJDfAQIgYE8wF7t2"
    "OUMBoMoYVTG2/I9fDeebLuA19eE/4erB3+UBAQ4gAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
    "AQEBAQEBAQEBAQEBDwQAAAAAARAE/////wABAwgoIwAAAAAAAAEEFgAUo8ax7kpJ2fKvO"
    "zgCl0dE+6kkFkoA"
)
assert run("sign", psbt, "07" * 32) == f"{signed}\n"
assert json.loads(run("inspect", signed)) == {
    **summary,
    "signature_inputs": 1,
    "partial_signatures": 1,
}
finalized = (
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQEfECcAAAAAAAAW"
    "ABSjxrHuSknZ8q87OAKXR0T7qSQWSgEIawJHMEQCIGw58gnq7lXKdQyeokTO4eBrQAUMz"
    "wcZjBgteyGAkN8BAiBgTzAXu3Y5QwGgyhhVMbb8j18N55su4DX14T/h6sHf5QEhApicC3"
    "bLVjlx/cm+8x7AbDVg8ySdbunl2DxXYlWW4F9vAQ4gAQEBAQEBAQEBAQEBAQEBAQEBAQ"
    "EBAQEBAQEBAQEBAQEBDwQAAAAAARAE/////wABAwgoIwAAAAAAAAEEFgAUo8ax7kpJ2fK"
    "vOzgCl0dE+6kkFkoA"
)
assert run("finalize", signed) == f"{finalized}\n"
assert json.loads(run("inspect", finalized)) == {
    **summary,
    "signature_inputs": 1,
    "final_inputs": 1,
}
extracted = (
    "020000000001010101010101010101010101010101010101010101010101010101010101010101000000"
    "0000ffffffff012823000000000000160014a3c6b1ee4a49d9f2af3b3802974744fba924164a02473044"
    "02206c39f209eaee55ca750c9ea244cee1e06b40050ccf07198c182d7b218090df010220604f3017bb76"
    "394301a0ca185531b6fc8f5f0de79b2ee035f5e13fe1eac1dfe5012102989c0b76cb563971fdc9bef31e"
    "c06c3560f3249d6ee9e5d83c57625596e05f6f00000000"
)
assert run("extract", finalized) == f"{extracted}\n"

print("ok")

#!/usr/bin/env python3
"""Independent BIP341 reference checker (no bitcoin libraries).

Recomputes, from first principles:
  - TapLeaf / TapBranch tagged hashes
  - control-block path application (leaf -> root) with lexicographic sorting
  - Q = lift_x(internal) + int(TapTweak(internal || merkle_root)) * G
  - output key x(Q) and parity bit, compared with the library's control blocks
    and tweakedPubkey.

Run: python3 check_cases.py cases.json
"""
import hashlib
import json
import sys

# --- secp256k1 primitives (pure python, from spec) --------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()

def lift_x(x: int):
    if x >= P:
        raise ValueError("x >= p")
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if pow(y, 2, P) != c:
        raise ValueError("not a curve point")
    return (x, y if y % 2 == 0 else P - y)

def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x3 = (lam * lam - a[0] - b[0]) % P
    return (x3, (lam * (a[0] - x3) - a[1]) % P)

def point_mul(k: int, pt):
    r = None
    add = pt
    while k:
        if k & 1:
            r = point_add(r, add)
        add = point_add(add, add)
        k >>= 1
    return r

def compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def tapleaf_hash(script: bytes, version: int) -> bytes:
    return tagged_hash("TapLeaf", bytes([version]) + compact_size(len(script)) + script)

def tapbranch_hash(a: bytes, b: bytes) -> bytes:
    x, y = (a, b) if a <= b else (b, a)
    return tagged_hash("TapBranch", x + y)

def tap_tweak(internal_x: bytes, merkle_root: bytes) -> int:
    t = int.from_bytes(tagged_hash("TapTweak", internal_x + merkle_root), "big")
    if t >= N:
        raise ValueError("tweak >= n")
    return t

def output_key(internal_x: bytes, merkle_root: bytes):
    t = tap_tweak(internal_x, merkle_root)
    pt = lift_x(int.from_bytes(internal_x, "big"))
    q = point_add(pt, point_mul(t, (Gx, Gy)))
    return q[0].to_bytes(32, "big"), q[1] % 2

# --- case verification -------------------------------------------------------
def main() -> int:
    cases = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "cases.json"))
    ok = fail = skip = 0
    for c in cases:
        tag = c["tag"]
        if tag == "path-129-must-throw":
            status = "OK" if c["threw"] else "FAIL(no throw, consensus-invalid output created)"
            print(f"[{status}] {tag}: {c.get('error')}")
            ok += c["threw"]
            fail += (not c["threw"])
            continue
        if tag.startswith("nested-depth-"):
            print(f"[info] {tag}: ms={c['ms']} error={c['error']}")
            skip += 1
            continue
        if tag == "tapleaf-op-true":
            ref = tapleaf_hash(b"\x51", 0xC0).hex()
            good = ref == c["tapLeafHash"]
            print(f"[{'OK' if good else 'FAIL'}] {tag}: lib={c['tapLeafHash']} ref={ref}")
            ok += good
            fail += (not good)
            continue

        internal = bytes.fromhex(c["internalKey"])
        lib_root = bytes.fromhex(c["tapMerkleRoot"]) if c["tapMerkleRoot"] else b""
        case_ok = True

        if tag == "key-path-only":
            x, par = output_key(internal, b"")
            case_ok = x.hex() == c["tweakedPubkey"]
        else:
            for leaf in c["leaves"]:
                script = bytes.fromhex(leaf["script"])
                version = leaf["version"]
                # 1) leaf hash
                h = tapleaf_hash(script, version)
                if h.hex() != leaf["hash"]:
                    print(f"  leaf-hash mismatch: lib={leaf['hash']} ref={h.hex()}")
                    case_ok = False
                    continue
                # 2) walk control-block path leaf -> root
                for sib_hex in leaf["path"]:
                    h = tapbranch_hash(h, bytes.fromhex(sib_hex))
                if h != lib_root:
                    print(f"  path does not reach root: got={h.hex()} root={lib_root.hex()}")
                    case_ok = False
                # 3) control block byte-level check
                cb = bytes.fromhex(leaf["controlBlock"])
                if cb[0] & 0xFE != version:
                    print(f"  control block version byte {cb[0]:#x} != leaf version {version:#x}")
                    case_ok = False
                if cb[1:33] != internal:
                    print("  control block internal key mismatch")
                    case_ok = False
                body = b"".join(bytes.fromhex(p) for p in leaf["path"])
                if cb[33:] != body:
                    print("  control block merkle path bytes mismatch")
                    case_ok = False
                # 4) parity: recompute output key from this leaf's root
                x, par = output_key(internal, h)
                if (cb[0] & 1) != par:
                    print(f"  parity bit mismatch: cb={cb[0] & 1} ref={par}")
                    case_ok = False
                if x.hex() != c["tweakedPubkey"]:
                    print(f"  output key mismatch: ref={x.hex()} lib={c['tweakedPubkey']}")
                    case_ok = False
        print(f"[{'OK' if case_ok else 'FAIL'}] {tag} ({len(c['leaves'])} leaves)")
        ok += case_ok
        fail += (not case_ok)
    print(f"\n== {ok} OK, {fail} FAIL, {skip} info ==")
    return 1 if fail else 0

if __name__ == "__main__":
    sys.exit(main())

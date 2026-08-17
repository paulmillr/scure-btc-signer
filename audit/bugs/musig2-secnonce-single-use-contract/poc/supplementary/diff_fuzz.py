#!/usr/bin/env python3
"""Differential fuzzer: @scure/btc-signer musig2.ts vs BIP327 reference.py.
Generates edge-case-heavy random inputs, runs both drivers, compares results."""
import json
import random
import subprocess
import sys

sys.path.insert(0, '/tmp/claude/opencode/bips/bip-0327')
import reference as R

NODE = '/tmp/claude/opencode/node-v24.19.0-linux-x64/bin/node'
TS_DRIVER = '/tmp/claude/opencode/harness/ts_driver.ts'
REF_DRIVER = '/tmp/claude/opencode/harness/ref_driver.py'
n = R.n
rng = random.Random(20260805)


def rand_scalar():
    return rng.randrange(1, n)


def rand_sk():
    return R.bytes_from_int(rand_scalar())


def pk_of(sk):
    return R.individual_pk(sk)


def rand_bytes(k):
    return bytes(rng.randrange(256) for _ in range(k))


def rand_tweak():
    r = rng.random()
    if r < 0.15:
        return bytes(32)  # zero tweak (valid)
    if r < 0.25:
        return R.bytes_from_int(n - 1)  # max valid
    if r < 0.30:
        return R.bytes_from_int(n)  # invalid: t >= n (both must fail)
    if r < 0.35:
        return R.bytes_from_int(n + rng.randrange(1, 2**128))  # invalid
    return rand_bytes(32)


def gen_key_list():
    """Random signer key list, heavy on duplicates/single/all-equal."""
    style = rng.random()
    sks = [rand_sk() for _ in range(rng.randrange(1, 4))]
    pks = [pk_of(s) for s in sks]
    if style < 0.2 and pks:
        return [pks[0]]  # single key
    if style < 0.4 and pks:
        return [pks[0]] * rng.randrange(2, 4)  # all equal
    if style < 0.65 and len(pks) >= 2:
        lst = pks + [pks[rng.randrange(len(pks))]]  # inject duplicate
        rng.shuffle(lst)
        return lst
    return pks


def gen_tweaks():
    v = rng.randrange(0, 4)
    return [rand_tweak() for _ in range(v)], [bool(rng.getrandbits(1)) for _ in range(v)]


def gen_nonce(pk, sk=None, aggpk=None, msg=None, extra=None):
    rand = rand_bytes(32)
    sec, pub = R.nonce_gen_internal(rand, sk, pk, aggpk, msg, extra)
    return bytes(sec), pub


def build_cases():
    cases = []
    # 1) key_agg + tweaks differential
    for _ in range(160):
        pubs = gen_key_list()
        tweaks, is_x = gen_tweaks()
        cases.append({'type': 'key_agg', 'pubkeys': [p.hex() for p in pubs],
                      'tweaks': [t.hex() for t in tweaks], 'is_xonly': is_x})
    # 2) nonce_gen differential, incl. omitted vs empty msg/aggpk/extra
    for i in range(60):
        sk = rand_sk()
        pk = pk_of(sk)
        msg = None
        mstyle = i % 3
        if mstyle == 1:
            msg = b''  # explicitly empty
        elif mstyle == 2:
            msg = rand_bytes(rng.randrange(1, 64))
        aggpk = rand_bytes(32) if rng.random() < 0.7 else None
        extra = rand_bytes(rng.randrange(0, 32)) if rng.random() < 0.7 else None
        cases.append({'type': 'nonce_gen', 'rand': rand_bytes(32).hex(), 'pk': pk.hex(),
                      'sk': sk.hex() if rng.random() < 0.8 else None,
                      'aggpk': aggpk.hex() if aggpk else None,
                      'msg': msg.hex() if msg is not None else None,
                      'extra_in': extra.hex() if extra else None})
    # 3) nonce_agg differential, incl. crafted infinity-sum aggregates
    for _ in range(40):
        u = rng.randrange(1, 4)
        pubs = []
        for _ in range(u):
            sk = rand_sk()
            _, pub = gen_nonce(pk_of(sk), sk)
            pubs.append(pub)
        cases.append({'type': 'nonce_agg', 'pubnonces': [p.hex() for p in pubs]})
    for _ in range(15):
        # crafted: R1 limbs sum to infinity, R2 limbs sum to infinity
        sk = rand_sk()
        pk = pk_of(sk)
        _, pub = gen_nonce(pk, sk)
        R1 = R.cpoint(pub[0:33])
        R2 = R.cpoint(pub[33:66])
        neg1 = R.cbytes(R.point_negate(R1))
        neg2 = R.cbytes(R.point_negate(R2))
        evil = neg1 + neg2
        cases.append({'type': 'nonce_agg', 'pubnonces': [pub.hex(), evil.hex()]})
    # 4) full roundtrip: sign + verify + sig_agg differential (also covers session_values)
    for _ in range(80):
        u = rng.randrange(1, 4)
        sks = [rand_sk() for _ in range(u)]
        pubs = [pk_of(s) for s in sks]
        if rng.random() < 0.3 and u >= 1:  # duplicate key list
            pubs = pubs + [pubs[0]]
            sks = sks + [sks[0]]
            u += 1
        tweaks, is_x = gen_tweaks()
        # filter invalid tweak cases here: sign path must not fail keyagg
        try:
            ctx = R.key_agg(pubs)
            for i, tw in enumerate(tweaks):
                ctx = R.apply_tweak(ctx, tw, is_x[i])
        except Exception:
            continue
        msg = rand_bytes(rng.randrange(0, 96))
        secs, pubs_n = [], []
        for i in range(u):
            sec, pub = gen_nonce(pubs[i], sks[i])
            secs.append(sec)
            pubs_n.append(pub)
        if rng.random() < 0.15 and u >= 2:
            # force infinity aggnonce via negated limbs for last signer
            agg = bytearray(R.nonce_agg(pubs_n))
            R1 = R.cpoint(bytes(pubs_n[0][0:33]))
            R2 = R.cpoint(bytes(pubs_n[0][33:66]))
            pubs_n[-1] = R.cbytes(R.point_negate(R1)) + R.cbytes(R.point_negate(R2))
            # recompute: sums of two equal-magnitude opposite points cancel
            pubs_n[0] = pubs_n[0]  # first stays
            pubs_n[1] = R.cbytes(R.point_negate(R.cpoint(bytes(pubs_n[0][0:33])))) + \
                R.cbytes(R.point_negate(R.cpoint(bytes(pubs_n[0][33:66]))))
        aggnonce = R.nonce_agg(pubs_n)
        common = {'aggnonce': aggnonce.hex(), 'pubkeys': [p.hex() for p in pubs],
                  'tweaks': [t.hex() for t in tweaks], 'is_xonly': is_x, 'msg': msg.hex()}
        cases.append(dict({'type': 'session_values'}, **common))
        psigs = []
        for i in range(u):
            cases.append(dict({'type': 'sign', 'secnonce': secs[i].hex(), 'sk': sks[i].hex()}, **common))
            # compute reference psig for sig_agg case below
            ctx2 = R.SessionContext(aggnonce, pubs, tweaks, is_x, msg)
            psigs.append(R.sign(bytearray(secs[i]), sks[i], ctx2))
            cases.append(dict({'type': 'verify', 'psig': psigs[-1].hex(),
                               'pubnonces': [p.hex() for p in pubs_n], 'index': i}, **common))
        cases.append(dict({'type': 'sig_agg', 'psigs': [p.hex() for p in psigs]}, **common))
    # 5) det_sign differential
    for _ in range(60):
        u = rng.randrange(1, 4)
        sks = [rand_sk() for _ in range(u)]
        pubs = [pk_of(s) for s in sks]
        tweaks, is_x = gen_tweaks()
        try:
            ctx = R.key_agg(pubs)
            for i, tw in enumerate(tweaks):
                ctx = R.apply_tweak(ctx, tw, is_x[i])
        except Exception:
            continue
        msg = rand_bytes(rng.randrange(0, 64))
        others = []
        for i in range(1, u):
            _, pub = gen_nonce(pubs[i], sks[i])
            others.append(pub)
        if not others:  # single-signer: aggothernonce is the empty sum? use own second nonce
            _, pub = gen_nonce(pubs[0], sks[0])
            others = [pub]
        aggother = R.nonce_agg(others)
        cases.append({'type': 'det_sign', 'sk': sks[0].hex(), 'aggothernonce': aggother.hex(),
                      'pubkeys': [p.hex() for p in pubs], 'tweaks': [t.hex() for t in tweaks],
                      'is_xonly': is_x, 'msg': msg.hex(),
                      'rand': rand_bytes(32).hex() if rng.random() < 0.5 else None})
    return cases


def norm_err(e):
    if e.startswith('InvalidContributionError:'):
        return e  # index + contribution compared exactly
    return 'ERROR'  # other errors: only require both sides to fail


def compare(case, a, b):
    if 'err' in a or 'err' in b:
        if 'err' not in a or 'err' not in b:
            return f'one-sided error: ref={a} ts={b}'
        ea, eb = norm_err(a['err']), norm_err(b['err'])
        if ea != eb:
            return f'error mismatch: ref={a["err"]} ts={b["err"]}'
        return None
    ka, kb = a['ok'], b['ok']
    if ka != kb:
        return f'result mismatch: ref={ka} ts={kb}'
    return None


def main():
    cases = build_cases()
    print(f'generated {len(cases)} cases', file=sys.stderr)
    payload = json.dumps(cases).encode()
    ref = subprocess.run(['python3', REF_DRIVER], input=payload, capture_output=True, check=True)
    ts = subprocess.run([NODE, TS_DRIVER], input=payload, capture_output=True, check=True)
    ref_out = json.loads(ref.stdout)
    ts_out = json.loads(ts.stdout)
    assert len(ref_out) == len(ts_out) == len(cases)
    fails = 0
    for i, (c, a, b) in enumerate(zip(cases, ref_out, ts_out)):
        # verify-case: reference returns verify_throw for NonceAgg failures; TS throws too
        m = compare(c, a, b)
        if m:
            fails += 1
            print(f'FAIL case {i}: {json.dumps(c)[:200]}\n  {m}', file=sys.stderr)
            if fails > 10:
                break
    print(f'{len(cases) - fails}/{len(cases)} differential cases match', file=sys.stderr)
    sys.exit(1 if fails else 0)


main()

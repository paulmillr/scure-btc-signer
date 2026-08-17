#!/usr/bin/env python3
"""Differential-test driver: BIP327 reference.py backend.
Reads a JSON list of cases on stdin, writes JSON results to stdout.
Each result is {"ok": ...} or {"err": "type:message"} so the two backends
can be compared semantically."""
import json
import sys

sys.path.insert(0, '/tmp/claude/opencode/bips/bip-0327')
import reference as R  # noqa: E402


def hx(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) else b


def run(case):
    t = case['type']
    if t == 'key_agg':
        pubs = [bytes.fromhex(x) for x in case['pubkeys']]
        tweaks = [bytes.fromhex(x) for x in case.get('tweaks', [])]
        is_x = case.get('is_xonly', [])
        ctx = R.key_agg(pubs)
        for i, tw in enumerate(tweaks):
            ctx = R.apply_tweak(ctx, tw, is_x[i])
        Q, gacc, tacc = ctx
        return {'aggpk': R.get_xonly_pk(ctx).hex(), 'gacc': str(gacc), 'tacc': str(tacc),
                'compressed': R.cbytes(Q).hex()}
    if t == 'nonce_gen':
        rand = bytes.fromhex(case['rand'])
        sk = bytes.fromhex(case['sk']) if case.get('sk') else None
        pk = bytes.fromhex(case['pk'])
        aggpk = bytes.fromhex(case['aggpk']) if case.get('aggpk') else None
        msg = bytes.fromhex(case['msg']) if case.get('msg') is not None else None
        extra = bytes.fromhex(case['extra_in']) if case.get('extra_in') else None
        sec, pub = R.nonce_gen_internal(rand, sk, pk, aggpk, msg, extra)
        return {'secnonce': hx(sec), 'pubnonce': hx(pub)}
    if t == 'nonce_agg':
        pns = [bytes.fromhex(x) for x in case['pubnonces']]
        return {'aggnonce': R.nonce_agg(pns).hex()}
    if t == 'session_values':
        aggnonce = bytes.fromhex(case['aggnonce'])
        pubs = [bytes.fromhex(x) for x in case['pubkeys']]
        tweaks = [bytes.fromhex(x) for x in case.get('tweaks', [])]
        is_x = case.get('is_xonly', [])
        msg = bytes.fromhex(case['msg'])
        ctx = R.SessionContext(aggnonce, pubs, tweaks, is_x, msg)
        Q, gacc, tacc, b, Rpt, e = R.get_session_values(ctx)
        return {'b': str(b), 'e': str(e), 'R': R.cbytes(Rpt).hex(),
                'gacc': str(gacc), 'tacc': str(tacc), 'Q': R.cbytes(Q).hex()}
    if t == 'sign':
        sec = bytearray(bytes.fromhex(case['secnonce']))
        sk = bytes.fromhex(case['sk'])
        aggnonce = bytes.fromhex(case['aggnonce'])
        pubs = [bytes.fromhex(x) for x in case['pubkeys']]
        tweaks = [bytes.fromhex(x) for x in case.get('tweaks', [])]
        is_x = case.get('is_xonly', [])
        msg = bytes.fromhex(case['msg'])
        ctx = R.SessionContext(aggnonce, pubs, tweaks, is_x, msg)
        psig = R.sign(sec, sk, ctx)
        return {'psig': psig.hex(), 'secnonce_after': hx(sec)}
    if t == 'det_sign':
        sk = bytes.fromhex(case['sk'])
        aggother = bytes.fromhex(case['aggothernonce'])
        pubs = [bytes.fromhex(x) for x in case['pubkeys']]
        tweaks = [bytes.fromhex(x) for x in case.get('tweaks', [])]
        is_x = case.get('is_xonly', [])
        msg = bytes.fromhex(case['msg'])
        rand = bytes.fromhex(case['rand']) if case.get('rand') else None
        pub, psig = R.deterministic_sign(sk, aggother, pubs, tweaks, is_x, msg, rand)
        return {'pubnonce': pub.hex(), 'psig': psig.hex()}
    if t == 'sig_agg':
        psigs = [bytes.fromhex(x) for x in case['psigs']]
        aggnonce = bytes.fromhex(case['aggnonce'])
        pubs = [bytes.fromhex(x) for x in case['pubkeys']]
        tweaks = [bytes.fromhex(x) for x in case.get('tweaks', [])]
        is_x = case.get('is_xonly', [])
        msg = bytes.fromhex(case['msg'])
        ctx = R.SessionContext(aggnonce, pubs, tweaks, is_x, msg)
        return {'sig': R.partial_sig_agg(psigs, ctx).hex()}
    if t == 'verify':
        psig = bytes.fromhex(case['psig'])
        pns = [bytes.fromhex(x) for x in case['pubnonces']]
        pubs = [bytes.fromhex(x) for x in case['pubkeys']]
        tweaks = [bytes.fromhex(x) for x in case.get('tweaks', [])]
        is_x = case.get('is_xonly', [])
        msg = bytes.fromhex(case['msg'])
        i = case['index']
        try:
            ok = R.partial_sig_verify(psig, pns, pubs, tweaks, is_x, msg, i)
            return {'verify': bool(ok)}
        except Exception as e:  # reference treats NonceAgg failure as hard fail
            return {'verify_throw': type(e).__name__}
    raise ValueError('unknown case type ' + t)


def main():
    cases = json.load(sys.stdin)
    out = []
    for c in cases:
        try:
            out.append({'ok': run(c)})
        except Exception as e:
            name = type(e).__name__
            if isinstance(e, R.InvalidContributionError):
                out.append({'err': f'InvalidContributionError:{e.signer}:{e.contrib}'})
            else:
                out.append({'err': f'{name}:{e}'})
    json.dump(out, sys.stdout)


main()

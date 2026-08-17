#!/usr/bin/env python3
"""Compare library digests vs the independent reference. Prints per-scheme matrix verdict."""
import json, collections, sys
specs = {c['id']: c for c in json.load(open('specs.json'))}
lib = json.load(open('lib_digests.json'))
ref = {r['id']: r for r in json.load(open('ref_digests.json'))}
by_scheme = collections.defaultdict(lambda: [0, 0])
divergent = []
for cid, spec in specs.items():
    ok = lib[cid] == ref[cid]['digest']
    by_scheme[spec['scheme']][ok] += 1
    if not ok:
        divergent.append((cid, spec, lib[cid], ref[cid]['digest']))
for s, (bad, good) in sorted(by_scheme.items()):
    print(f'{s}: {good} equal, {bad} divergent')
for cid, spec, l, r in divergent:
    kind = 'idx>=nIn' if spec['idx'] >= len(spec['inputs']) else 'SINGLE-missing-output'
    print(f"DIVERGENT {cid} {spec['scheme']} ht={spec['hashType']:#x} {kind}: lib={l[:16]}.. ref={r[:16]}..")

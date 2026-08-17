#!/usr/bin/env python3
"""Independent sighash reference, transcribed from Bitcoin Core's
test/functional/test_framework/script.py @ 5871b5b5ab57a0caf9b7514eb162c491c83281d5
(the exact revision cited in src/transaction.ts:1112 of @scure/btc-signer).

Implements: LegacySignatureHash (with HASH_ONE exception), SegwitV0SignatureHash,
TaprootSignatureHash. Used as the differential oracle for @scure/btc-signer.
"""
import hashlib
import json
import struct
import sys

SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80
LEAF_VERSION_TAPSCRIPT = 0xC0

OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_CODESEPARATOR = 0xAB

HASH_ONE = b'\x01' + b'\x00' * 31


def sha256(b):
    return hashlib.sha256(b).digest()


def hash256(b):
    return sha256(sha256(b))


def tagged_hash(tag, msg):
    th = sha256(tag.encode())
    return sha256(th + th + msg)


def ser_compact_size(n):
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def ser_string(b):
    return ser_compact_size(len(b)) + b


class COutPoint:
    def __init__(self, txid_display_hex, n):
        # internal uint256 bytes are display-order reversed
        self.hash = bytes.fromhex(txid_display_hex)[::-1]
        self.n = n

    def serialize(self):
        return self.hash + struct.pack('<I', self.n)


class CTxIn:
    def __init__(self, prevout, scriptSig=b'', nSequence=0xFFFFFFFF):
        self.prevout = prevout
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def serialize(self):
        return self.prevout.serialize() + ser_string(self.scriptSig) + struct.pack('<I', self.nSequence)


class CTxOut:
    def __init__(self, nValue=0, scriptPubKey=b''):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def serialize(self):
        return struct.pack('<q', self.nValue) + ser_string(self.scriptPubKey)


class CTransaction:
    def __init__(self, nVersion, vin, vout, nLockTime):
        self.nVersion = nVersion
        self.vin = vin
        self.vout = vout
        self.nLockTime = nLockTime

    def serialize_without_witness(self):
        r = struct.pack('<i', self.nVersion)
        r += ser_compact_size(len(self.vin))
        for i in self.vin:
            r += i.serialize()
        r += ser_compact_size(len(self.vout))
        for o in self.vout:
            r += o.serialize()
        r += struct.pack('<I', self.nLockTime)
        return r


def raw_iter(script):
    """Mirror of CScript.raw_iter: yields (opcode, data, sop_idx). Raises on truncation."""
    i = 0
    while i < len(script):
        sop_idx = i
        opcode = script[i]
        i += 1
        if opcode > OP_PUSHDATA4:
            yield (opcode, None, sop_idx)
        else:
            if opcode < OP_PUSHDATA1:
                datasize = opcode
            elif opcode == OP_PUSHDATA1:
                if i >= len(script):
                    raise ValueError('PUSHDATA1: missing data length')
                datasize = script[i]
                i += 1
            elif opcode == OP_PUSHDATA2:
                if i + 1 >= len(script):
                    raise ValueError('PUSHDATA2: missing data length')
                datasize = script[i] + (script[i + 1] << 8)
                i += 2
            else:
                if i + 3 >= len(script):
                    raise ValueError('PUSHDATA4: missing data length')
                datasize = script[i] + (script[i + 1] << 8) + (script[i + 2] << 16) + (script[i + 3] << 24)
                i += 4
            data = bytes(script[i:i + datasize])
            if len(data) < datasize:
                raise ValueError('truncated data')
            i += datasize
            yield (opcode, data, sop_idx)


def find_and_delete_codeseparator(script):
    """Consensus FindAndDelete(script, CScript([OP_CODESEPARATOR]))."""
    sig = bytes([OP_CODESEPARATOR])
    r = b''
    last_sop_idx = sop_idx = 0
    skip = True
    for (opcode, data, sop_idx) in raw_iter(script):
        if not skip:
            r += script[last_sop_idx:sop_idx]
        last_sop_idx = sop_idx
        if script[sop_idx:sop_idx + len(sig)] == sig:
            skip = True
        else:
            skip = False
    if not skip:
        r += script[last_sop_idx:]
    return r


def legacy_signature_msg(script, txTo, inIdx, hashtype):
    if inIdx >= len(txTo.vin):
        return None
    txtmp = CTransaction(txTo.nVersion,
                         [CTxIn(i.prevout, b'', i.nSequence) for i in txTo.vin],
                         [CTxOut(o.nValue, o.scriptPubKey) for o in txTo.vout],
                         txTo.nLockTime)
    txtmp.vin[inIdx].scriptSig = find_and_delete_codeseparator(script)
    if (hashtype & 0x1f) == SIGHASH_NONE:
        txtmp.vout = []
        for i in range(len(txtmp.vin)):
            if i != inIdx:
                txtmp.vin[i].nSequence = 0
    elif (hashtype & 0x1f) == SIGHASH_SINGLE:
        outIdx = inIdx
        if outIdx >= len(txtmp.vout):
            return None
        tmp = txtmp.vout[outIdx]
        txtmp.vout = []
        for _ in range(outIdx):
            txtmp.vout.append(CTxOut(-1))
        txtmp.vout.append(tmp)
        for i in range(len(txtmp.vin)):
            if i != inIdx:
                txtmp.vin[i].nSequence = 0
    if hashtype & SIGHASH_ANYONECANPAY:
        tmp = txtmp.vin[inIdx]
        txtmp.vin = [tmp]
    s = txtmp.serialize_without_witness()
    s += struct.pack('<I', hashtype)
    return s


def legacy_signature_hash(script, txTo, inIdx, hashtype):
    msg = legacy_signature_msg(script, txTo, inIdx, hashtype)
    if msg is None:
        return HASH_ONE
    return hash256(msg)


def segwit_v0_signature_msg(script, txTo, inIdx, hashtype, amount):
    hashPrevouts = b'\x00' * 32
    hashSequence = b'\x00' * 32
    hashOutputs = b'\x00' * 32
    if not (hashtype & SIGHASH_ANYONECANPAY):
        hashPrevouts = hash256(b''.join(i.prevout.serialize() for i in txTo.vin))
    if (not (hashtype & SIGHASH_ANYONECANPAY)
            and (hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
        hashSequence = hash256(b''.join(struct.pack('<I', i.nSequence) for i in txTo.vin))
    if (hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE:
        hashOutputs = hash256(b''.join(o.serialize() for o in txTo.vout))
    elif (hashtype & 0x1f) == SIGHASH_SINGLE and inIdx < len(txTo.vout):
        hashOutputs = hash256(txTo.vout[inIdx].serialize())
    ss = struct.pack('<i', txTo.nVersion)
    ss += hashPrevouts
    ss += hashSequence
    ss += txTo.vin[inIdx].prevout.serialize()
    ss += ser_string(script)
    ss += struct.pack('<q', amount)
    ss += struct.pack('<I', txTo.vin[inIdx].nSequence)
    ss += hashOutputs
    ss += struct.pack('<I', txTo.nLockTime)
    ss += struct.pack('<I', hashtype)
    return ss


def segwit_v0_signature_hash(script, txTo, inIdx, hashtype, amount):
    return hash256(segwit_v0_signature_msg(script, txTo, inIdx, hashtype, amount))


def taproot_signature_msg(txTo, spent_utxos, hash_type, input_index=0,
                          scriptpath=False, script=b'', codeseparator_pos=-1,
                          annex=None, leaf_ver=LEAF_VERSION_TAPSCRIPT):
    assert len(txTo.vin) == len(spent_utxos)
    assert input_index < len(txTo.vin)
    out_type = SIGHASH_ALL if hash_type == 0 else hash_type & 3
    in_type = hash_type & SIGHASH_ANYONECANPAY
    spk = spent_utxos[input_index].scriptPubKey
    ss = bytes([0, hash_type])
    ss += struct.pack('<i', txTo.nVersion)
    ss += struct.pack('<I', txTo.nLockTime)
    if in_type != SIGHASH_ANYONECANPAY:
        ss += sha256(b''.join(i.prevout.serialize() for i in txTo.vin))
        ss += sha256(b''.join(struct.pack('<q', u.nValue) for u in spent_utxos))
        ss += sha256(b''.join(ser_string(u.scriptPubKey) for u in spent_utxos))
        ss += sha256(b''.join(struct.pack('<I', i.nSequence) for i in txTo.vin))
    if out_type == SIGHASH_ALL:
        ss += sha256(b''.join(o.serialize() for o in txTo.vout))
    spend_type = 0
    if annex is not None:
        spend_type |= 1
    if scriptpath:
        spend_type |= 2
    ss += bytes([spend_type])
    if in_type == SIGHASH_ANYONECANPAY:
        ss += txTo.vin[input_index].prevout.serialize()
        ss += struct.pack('<q', spent_utxos[input_index].nValue)
        ss += ser_string(spk)
        ss += struct.pack('<I', txTo.vin[input_index].nSequence)
    else:
        ss += struct.pack('<I', input_index)
    if spend_type & 1:
        ss += sha256(ser_string(annex))
    if out_type == SIGHASH_SINGLE:
        if input_index < len(txTo.vout):
            ss += sha256(txTo.vout[input_index].serialize())
        else:
            ss += bytes(32)
    if scriptpath:
        ss += tagged_hash('TapLeaf', bytes([leaf_ver]) + ser_string(script))
        ss += bytes([0])
        ss += struct.pack('<i', codeseparator_pos)
    return ss


def taproot_signature_hash(*args, **kwargs):
    return tagged_hash('TapSighash', taproot_signature_msg(*args, **kwargs))


def spec_to_tx(spec):
    vin = [CTxIn(COutPoint(i['txid'], i['vout']), b'', i['sequence']) for i in spec['inputs']]
    vout = [CTxOut(o['amount'], bytes.fromhex(o['script'])) for o in spec['outputs']]
    return CTransaction(spec['version'], vin, vout, spec['locktime'])


def compute(spec):
    tx = spec_to_tx(spec)
    idx = spec['idx']
    ht = spec['hashType']
    scheme = spec['scheme']
    if scheme == 'legacy':
        return legacy_signature_hash(bytes.fromhex(spec['scriptCode']), tx, idx, ht).hex()
    elif scheme == 'v0':
        return segwit_v0_signature_hash(bytes.fromhex(spec['scriptCode']), tx, idx, ht,
                                        spec['amounts'][idx]).hex()
    elif scheme == 'v1':
        spent = [CTxOut(a, bytes.fromhex(s)) for a, s in zip(spec['amounts'], spec['prevOutScripts'])]
        annex = bytes.fromhex(spec['annex']) if spec['annex'] is not None else None
        scriptpath = spec['leafScript'] is not None
        script = bytes.fromhex(spec['leafScript']) if scriptpath else b''
        return taproot_signature_hash(tx, spent, ht, idx, scriptpath, script,
                                      spec['codeSep'], annex, spec['leafVer']).hex()
    raise ValueError(scheme)


def main():
    cases = json.load(open(sys.argv[1]))
    out = []
    for c in cases:
        try:
            digest = compute(c)
            err = None
        except Exception as e:
            digest = None
            err = f'{type(e).__name__}: {e}'
        out.append({'id': c['id'], 'digest': digest, 'error': err})
    json.dump(out, open(sys.argv[2], 'w'))
    print(f'computed {len(out)} reference digests')


if __name__ == '__main__':
    main()

import { Coder, hex, utf8 } from '@scure/base';
import * as P from 'micro-packed';
import { OptScript, CustomScript } from './payment.js';
import { Script, ScriptType, MAX_SCRIPT_BYTE_LENGTH } from './script.js';
import { Bytes, isBytes, concatBytes } from './utils.js';

const PROTOCOL_ID = /* @__PURE__ */ utf8.decode('ord');

// Binary JSON-like encoding: [RFC 7049](https://www.rfc-editor.org/rfc/rfc7049)
// And partially [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html): without tagged values.
// Used for metadata encoding in ordinals and passkeys. Complex, but efficient encoding.

const isNegZero = (x: number) => x === 0 && 1 / x < 0;

// Float16Array is not available in JS as per Apr 2024.
// For now, we implement it using RFC 8949 like technique,
// while preserving Infinity and NaN. f32 rounding would be too slow.
// https://github.com/tc39/proposal-float16array
const F16BE = P.wrap({
  encodeStream(w, value: number) {
    // We simple encode popular values as bytes
    if (value === Infinity) return w.bytes(new Uint8Array([0x7c, 0x00]));
    if (value === -Infinity) return w.bytes(new Uint8Array([0xfc, 0x00]));
    if (Number.isNaN(value)) return w.bytes(new Uint8Array([0x7e, 0x00]));
    if (isNegZero(value)) return w.bytes(new Uint8Array([0x80, 0x00]));
    throw w.err('f16: not implemented');
  },
  decodeStream: (r) => {
    // decode_half from RFC 8949
    const half = P.U16BE.decodeStream(r);
    const exp = (half & 0x7c00) >> 10;
    const mant = half & 0x03ff;
    let val: number;
    if (exp === 0) val = 6.103515625e-5 * (mant / 1024);
    else if (exp !== 31) val = Math.pow(2, exp - 15) * (1 + mant / 1024);
    else val = mant ? NaN : Infinity;
    return half & 0x8000 ? -val : val;
  },
});

const createView = (arr: Uint8Array) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

const f32 = (le?: boolean) =>
  P.wrap({
    encodeStream(w, value: number) {
      if (Math.fround(value) !== value) throw w.err(`f32: wrong value=${value}`);
      const buf = new Uint8Array(4);
      createView(buf).setFloat32(0, value, le);
      w.bytes(buf);
    },
    decodeStream: (r) => createView(r.bytes(4)).getFloat32(0, le),
  });

const f64 = (le?: boolean) =>
  P.wrap({
    encodeStream(w, value: number) {
      // no validation, any JS number can be encoded as float64
      const buf = new Uint8Array(8);
      createView(buf).setFloat64(0, value, le);
      w.bytes(buf);
    },
    decodeStream: (r) => createView(r.bytes(8)).getFloat64(0, le),
  });

const F32BE = /* @__PURE__ */ f32(false); // const F32LE = /* @__PURE__ */ f32(true);
const F64BE = /* @__PURE__ */ f64(false); // const F64LE = /* @__PURE__ */ f64(true);

const INFO = P.bits(5); // additional info
const U64LEN = P.apply(P.U64BE, P.coders.number);

// Number/lengths limits
const CBOR_LIMITS: Record<
  number,
  [number | bigint, P.CoderType<number> | P.CoderType<bigint>, P.CoderType<number>]
> = {
  24: [2 ** 8 - 1, P.U8, P.U8],
  25: [2 ** 16 - 1, P.U16BE, P.U16BE],
  26: [2 ** 32 - 1, P.U32BE, P.U32BE],
  27: [2n ** 64n - 1n, P.U64BE, U64LEN],
};

const cborUint = P.wrap({
  encodeStream(w, value: number | bigint) {
    if (value < 24) return INFO.encodeStream(w, typeof value === 'bigint' ? Number(value) : value);
    for (const ai in CBOR_LIMITS) {
      const [limit, intCoder, _] = CBOR_LIMITS[ai];
      if (value > limit) continue;
      INFO.encodeStream(w, Number(ai));
      return (intCoder.encodeStream as any)(w, value);
    }
    throw w.err(`cbor/uint: wrong value=${value}`);
  },
  decodeStream(r) {
    const ai = INFO.decodeStream(r);
    if (ai < 24) return ai;
    const intCoder = CBOR_LIMITS[ai][1];
    if (!intCoder) throw r.err(`cbor/uint wrong additional information=${ai}`);
    return intCoder.decodeStream(r);
  },
});

const cborNegint = P.wrap({
  encodeStream: (w, v: number | bigint) =>
    cborUint.encodeStream(w, typeof v === 'bigint' ? -(v + 1n) : -(v + 1)),
  decodeStream(r) {
    const v = cborUint.decodeStream(r);
    return typeof v === 'bigint' ? -1n - v : -1 - v;
  },
});

const cborArrLength = <T>(inner: P.CoderType<T>): P.CoderType<T[]> =>
  P.wrap({
    encodeStream(w, value: T[]) {
      if (value.length < 24) {
        INFO.encodeStream(w, value.length);
        P.array(value.length, inner).encodeStream(w, value);
        return;
      }
      for (const ai in CBOR_LIMITS) {
        const [limit, _, lenCoder] = CBOR_LIMITS[ai];
        if (value.length < limit) {
          INFO.encodeStream(w, Number(ai));
          P.array(lenCoder, inner).encodeStream(w, value);
          return;
        }
      }
      throw w.err(`cbor/lengthArray: wrong value=${value}`);
    },
    decodeStream(r): T[] {
      const ai = INFO.decodeStream(r);
      if (ai < 24) return P.array(ai, inner).decodeStream(r);
      // array can have indefinite-length
      if (ai === 31) return P.array(new Uint8Array([0xff]), inner).decodeStream(r);
      const lenCoder = CBOR_LIMITS[ai][2];
      if (!lenCoder) throw r.err(`cbor/lengthArray wrong length=${ai}`);
      return P.array(lenCoder, inner).decodeStream(r);
    },
  });

// for strings/bytestrings
const cborLength = <T>(
  fn: (len: P.Length) => P.CoderType<T>,
  // Indefinity-length strings accept other elements with different types, we validate that later
  def: P.CoderType<any>
): P.CoderType<T | T[]> =>
  P.wrap({
    encodeStream(w, value: T | T[]) {
      if (Array.isArray(value))
        throw new Error('cbor/length: encoding indefinite-length strings not supported');
      const bytes = fn(null).encode(value);
      if (bytes.length < 24) {
        INFO.encodeStream(w, bytes.length);
        w.bytes(bytes);
        return;
      }
      for (const ai in CBOR_LIMITS) {
        const [limit, _, lenCoder] = CBOR_LIMITS[ai];
        if (bytes.length < limit) {
          INFO.encodeStream(w, Number(ai));
          lenCoder.encodeStream(w, bytes.length);
          w.bytes(bytes);
          return;
        }
      }
      throw w.err(`cbor/lengthArray: wrong value=${value}`);
    },
    decodeStream(r): T | T[] {
      const ai = INFO.decodeStream(r);
      if (ai < 24) return fn(ai).decodeStream(r);
      if (ai === 31) return P.array(new Uint8Array([0xff]), def).decodeStream(r);
      const lenCoder = CBOR_LIMITS[ai][2];
      if (!lenCoder) throw r.err(`cbor/length wrong length=${ai}`);
      return fn(lenCoder).decodeStream(r);
    },
  });

const cborSimple: P.CoderType<boolean | null | undefined | number> = P.wrap({
  encodeStream(w, value) {
    if (value === false) return INFO.encodeStream(w, 20);
    if (value === true) return INFO.encodeStream(w, 21);
    if (value === null) return INFO.encodeStream(w, 22);
    if (value === undefined) return INFO.encodeStream(w, 23);
    if (typeof value !== 'number') throw w.err(`cbor/simple: wrong value type=${typeof value}`);
    // Basic values encoded as f16
    if (isNegZero(value) || Number.isNaN(value) || value === Infinity || value === -Infinity) {
      INFO.encodeStream(w, 25);
      return F16BE.encodeStream(w, value);
    }
    // If can be encoded as F32 without rounding
    if (Math.fround(value) === value) {
      INFO.encodeStream(w, 26);
      return F32BE.encodeStream(w, value);
    }
    INFO.encodeStream(w, 27);
    return F64BE.encodeStream(w, value);
  },
  decodeStream(r) {
    const ai = INFO.decodeStream(r);
    if (ai === 20) return false;
    if (ai === 21) return true;
    if (ai === 22) return null;
    if (ai === 23) return undefined;
    // ai === 24 is P.U8 with simple, reserved
    if (ai === 25) return F16BE.decodeStream(r);
    if (ai === 26) return F32BE.decodeStream(r);
    if (ai === 27) return F64BE.decodeStream(r);
    throw r.err('cbor/simple: unassigned');
  },
});

export type CborValue =
  | { TAG: 'uint'; data: number | bigint }
  | { TAG: 'negint'; data: number | bigint }
  | { TAG: 'simple'; data: boolean | null | undefined | number }
  | { TAG: 'string'; data: string }
  | { TAG: 'bytes'; data: Bytes }
  | { TAG: 'array'; data: CborValue[] }
  | { TAG: 'map'; data: [CborValue][] }
  | { TAG: 'tag'; data: [CborValue, CborValue] };

const cborValue: P.CoderType<CborValue> = P.mappedTag(P.bits(3), {
  uint: [0, cborUint], // An unsigned integer in the range 0..264-1 inclusive.
  negint: [1, cborNegint], // A negative integer in the range -264..-1 inclusive
  bytes: [2, P.lazy(() => cborLength(P.bytes, cborValue))], // A byte string.
  string: [3, P.lazy(() => cborLength(P.string, cborValue))], // A text string (utf8)
  array: [4, cborArrLength(P.lazy(() => cborValue))], // An array of data items
  map: [5, P.lazy(() => cborArrLength(P.tuple([cborValue, cborValue])))], // A map of pairs of data items
  tag: [6, P.tuple([cborUint, P.lazy(() => cborValue)] as const)], // A tagged data item ("tag") whose tag number
  simple: [7, cborSimple], // Floating-point numbers and simple values, as well as the "break" stop code
});

export const CBOR = P.apply(cborValue, {
  encode(from: CborValue): any {
    let value = from.data;
    if (from.TAG === 'bytes') {
      if (isBytes(value)) return value;
      const chunks = [];
      if (!Array.isArray(value))
        throw new Error(`CBOR: wrong indefinite-length bytestring=${value}`);
      for (const c of value as any) {
        if (c.TAG !== 'bytes' || !isBytes(c.data))
          throw new Error(`CBOR: wrong indefinite-length bytestring=${c}`);
        chunks.push(c.data);
      }
      return concatBytes(...chunks);
    }
    if (from.TAG === 'string') {
      if (typeof value === 'string') return value;
      if (!Array.isArray(value)) throw new Error(`CBOR: wrong indefinite-length string=${value}`);
      let res = '';
      for (const c of value as any) {
        if (c.TAG !== 'string' || typeof c.data !== 'string')
          throw new Error(`CBOR: wrong indefinite-length string=${c}`);
        res += c.data;
      }
      return res;
    }
    if (from.TAG === 'array' && Array.isArray(value)) value = value.map((i: any) => this.encode(i));
    if (from.TAG === 'map' && typeof value === 'object' && value !== null) {
      return Object.fromEntries(
        (from.data as any).map(([k, v]: [any, any]) => [this.encode(k), this.encode(v)])
      );
    }
    if (from.TAG === 'tag') throw new Error('not implemented');
    return value;
  },
  decode(data: any): any {
    if (typeof data === 'bigint') {
      return data < 0n ? { TAG: 'negint', data } : { TAG: 'uint', data };
    }
    if (typeof data === 'string') return { TAG: 'string', data };
    if (isBytes(data)) return { TAG: 'bytes', data };
    if (Array.isArray(data)) return { TAG: 'array', data: data.map((i) => this.decode(i)) };
    if (typeof data === 'number' && Number.isSafeInteger(data) && !isNegZero(data)) {
      return data < 0 ? { TAG: 'negint', data } : { TAG: 'uint', data };
    }
    if (
      typeof data === 'boolean' ||
      typeof data === 'number' ||
      data === null ||
      data === undefined
    ) {
      return { TAG: 'simple', data: data };
    }
    if (typeof data === 'object') {
      return { TAG: 'map', data: Object.entries(data).map((kv) => kv.map((i) => this.decode(i))) };
    }
    throw new Error('unknown type');
  },
});

function splitChunks(buf: Bytes): Bytes[] {
  const res = [];
  for (let i = 0; i < buf.length; i += MAX_SCRIPT_BYTE_LENGTH)
    res.push(buf.subarray(i, i + MAX_SCRIPT_BYTE_LENGTH));
  return res;
}

const RawInscriptionId = /* @__PURE__ */ P.tuple([
  P.bytes(32, true),
  P.apply(P.bigint(4, true, false, false), P.coders.number),
] as const);

export const InscriptionId: P.Coder<string, Bytes> = {
  encode(data: string) {
    const [txId, index] = data.split('i', 2);
    if (`${+index}` !== index) throw new Error(`InscriptionId wrong index: ${index}`);
    return RawInscriptionId.encode([hex.decode(txId), +index]);
  },
  decode(data: Bytes) {
    const [txId, index] = RawInscriptionId.decode(data);
    return `${hex.encode(txId)}i${index}`;
  },
};

const TagEnum = {
  // Would be simpler to have body tag here,
  // but body chunks don't have body tag near them
  contentType: 1,
  pointer: 2,
  parent: 3,
  metadata: 5,
  metaprotocol: 7,
  contentEncoding: 9,
  delegate: 11,
  rune: 13,
  note: 15,
  // Unrecognized even tag makes inscription unbound
  // unbound: 66,
  // Odd fields are ignored
  // nop: 255,
};

const TagCoderInternal = /* @__PURE__ */ P.map(P.U8, TagEnum);
type TagName = keyof typeof TagEnum;
type TagRaw = { tag: Bytes; data: Bytes };

const TagCoders = /* @__PURE__ */ {
  pointer: P.bigint(8, true, false, false), // U64
  contentType: P.string(null),
  parent: InscriptionId,
  metadata: CBOR,
  metaprotocol: P.string(null),
  contentEncoding: P.string(null),
  delegate: InscriptionId,
  rune: P.bigint(16, true, false, false), // U128
  note: P.string(null),
  // unbound: P.bytes(null),
  // nop: P.bytes(null),
};

export type Tags = { [K in keyof typeof TagCoders]: P.UnwrapCoder<(typeof TagCoders)[K]> } & {
  unknown?: [Bytes, Bytes][];
};
// We can't use mappedTag here, because tags can be split in chunks
const TagCoder: P.Coder<TagRaw[], Tags> = {
  encode(from: TagRaw[]): Tags {
    const tmp: Record<string, Bytes[]> = {};
    const unknown: [Bytes, Bytes][] = [];
    // collect tag parts
    for (const { tag, data } of from) {
      try {
        const tagName = TagCoderInternal.decode(tag);
        if (!tmp[tagName]) tmp[tagName] = [];
        tmp[tagName].push(data);
      } catch (e) {
        unknown.push([tag, data]);
      }
    }
    const res: Partial<Tags> = {};
    if (unknown.length) res.unknown = unknown;
    for (const field in tmp) {
      if (field === 'parent' && tmp[field].length > 1) {
        res[field as TagName] = tmp[field].map((i) => TagCoders.parent.decode(i));
        continue;
      }
      res[field as TagName] = TagCoders[field as TagName].decode(concatBytes(...tmp[field]));
    }
    return res as Tags;
  },
  decode(to: Tags): TagRaw[] {
    const res: TagRaw[] = [];
    for (const field in to) {
      if (field === 'unknown') continue;
      const tagName = TagCoderInternal.encode(field);
      if (field === 'parent' && Array.isArray(to.parent)) {
        for (const p of to.parent) res.push({ tag: tagName, data: TagCoders.parent.encode(p) });
        continue;
      }
      const bytes = TagCoders[field as TagName].encode(to[field as TagName]);
      for (const data of splitChunks(bytes)) res.push({ tag: tagName, data });
    }
    if (to.unknown) {
      if (!Array.isArray(to.unknown)) throw new Error('ordinals/TagCoder: unknown should be array');
      for (const [tag, data] of to.unknown) res.push({ tag, data });
    }
    return res;
  },
};

type Inscription = { tags: Tags; body: Bytes; cursed?: boolean };
type OutOrdinalRevealType = {
  type: 'tr_ord_reveal';
  pubkey: Bytes;
  inscriptions: Inscription[];
};

const parseEnvelopes = (script: ScriptType, pos = 0) => {
  if (!Number.isSafeInteger(pos)) throw new Error(`parseInscription: wrong pos=${typeof pos}`);
  const envelopes = [];
  // Inscriptions with broken parsing are called 'cursed' (stutter or pushnum)
  let stutter = false;
  main: for (; pos < script.length; pos++) {
    const instr = script[pos];
    if (instr !== 0) continue;
    if (script[pos + 1] !== 'IF') {
      if (script[pos + 1] === 0) stutter = true;
      continue main;
    }
    if (!isBytes(script[pos + 2]) || !P.equalBytes(script[pos + 2] as any, PROTOCOL_ID)) {
      if (script[pos + 2] === 0) stutter = true;
      continue main;
    }
    let pushnum = false;
    const payload: ScriptType = []; // bytes or 0
    for (let j = pos + 3; j < script.length; j++) {
      const op = script[j];
      // done
      if (op === 'ENDIF') {
        envelopes.push({ start: pos + 3, end: j, pushnum, payload, stutter });
        pos = j;
        break;
      }
      if (op === '1NEGATE') {
        pushnum = true;
        payload.push(new Uint8Array([0x81]));
        continue;
      }
      if (typeof op === 'number' && 1 <= op && op <= 16) {
        pushnum = true;
        payload.push(new Uint8Array([op]));
        continue;
      }
      if (isBytes(op) || op === 0) {
        payload.push(op);
        continue;
      }
      stutter = false;
      break;
    }
  }
  return envelopes;
};

// Additional API for parsing inscriptions
export const parseInscriptions = (script: ScriptType, strict = false) => {
  if (strict && (!isBytes(script[0]) || script[0].length !== 32)) return;
  if (strict && script[1] !== 'CHECKSIG') return;

  const envelopes = parseEnvelopes(script);
  const inscriptions: Inscription[] = [];
  // Check that all inscriptions are sequential inside script
  let pos = 5;
  for (const envelope of envelopes) {
    if (strict && (envelope.stutter || envelope.pushnum)) return;
    if (strict && envelope.start !== pos) return;
    const { payload } = envelope;
    let i = 0;
    const tags: TagRaw[] = [];
    for (; i < payload.length && payload[i] !== 0; i += 2) {
      const tag = payload[i];
      const data = payload[i + 1];
      if (!isBytes(tag)) throw new Error('parseInscription: non-bytes tag');
      if (!isBytes(data)) throw new Error('parseInscription: non-bytes tag data');
      tags.push({ tag, data });
    }
    while (payload[i] === 0 && i < payload.length) i++;

    const chunks = [];
    for (; i < payload.length; i++) {
      if (!isBytes(payload[i])) break;
      chunks.push(payload[i] as Bytes);
    }
    inscriptions.push({
      tags: TagCoder.encode(tags),
      body: concatBytes(...chunks),
      cursed: envelope.pushnum || envelope.stutter,
    });
    pos = envelope.end + 4;
  }
  if (pos - 3 !== script.length) return;
  return inscriptions;
};

/**
 * Parse inscriptions from reveal tx input witness (tx.inputs[0].finalScriptWitness)
 */
export const parseWitness = (witness: Bytes[]) => {
  if (witness.length !== 3) throw new Error('Wrong witness');
  // We don't validate other parts of witness here since we want to parse
  // as much stuff as possible. When creating inscription, it is done more strictly
  return parseInscriptions(Script.decode(witness[1]));
};

export const OutOrdinalReveal: Coder<OptScript, OutOrdinalRevealType | undefined> & CustomScript = {
  encode(from: ScriptType): OutOrdinalRevealType | undefined {
    const res: Partial<OutOrdinalRevealType> = { type: 'tr_ord_reveal' };
    try {
      res.inscriptions = parseInscriptions(from, true);
      res.pubkey = from[0] as Bytes;
    } catch (e) {
      return;
    }
    return res as OutOrdinalRevealType;
  },
  decode: (to: OutOrdinalRevealType): OptScript => {
    if (to.type !== 'tr_ord_reveal') return;
    const out: ScriptType = [to.pubkey, 'CHECKSIG'];
    for (const { tags, body } of to.inscriptions) {
      out.push(0, 'IF', PROTOCOL_ID);
      const rawTags = TagCoder.decode(tags);
      for (const tag of rawTags) out.push(tag.tag, tag.data);
      // Body
      out.push(0);
      for (const c of splitChunks(body)) out.push(c);
      out.push('ENDIF');
    }
    return out as any;
  },
  finalizeTaproot: (script, parsed, signatures) => {
    if (signatures.length !== 1) throw new Error('tr_ord_reveal/finalize: wrong signatures array');
    const [{ pubKey }, sig] = signatures[0];
    if (!P.equalBytes(pubKey, parsed.pubkey)) return;
    return [sig, script];
  },
};

/**
 * Create reveal transaction. Inscription created on spending output from this address by
 * revealing taproot script.
 */
export function p2tr_ord_reveal(pubkey: Bytes, inscriptions: Inscription[]) {
  return {
    type: 'tr_ord_reveal',
    script: P.apply(Script, P.coders.match([OutOrdinalReveal])).encode({
      type: 'tr_ord_reveal',
      pubkey,
      inscriptions,
    }),
  };
}

// Internal methods for tests
export const __test__ = { TagCoders, TagCoder, parseEnvelopes };

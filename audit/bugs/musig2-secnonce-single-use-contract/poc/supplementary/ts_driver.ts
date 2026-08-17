// Differential-test driver: @scure/btc-signer musig2.ts backend.
// Reads the same JSON case list as ref_driver.py on stdin, writes JSON results.
import * as musig2 from '<worktree>/src/musig2.ts';

const hx = (u: Uint8Array) => Buffer.from(u).toString('hex');
const un = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));

function errString(e: any): string {
  if (e instanceof musig2.InvalidContributionErr)
    return `InvalidContributionError:${e.idx}:${e.message}`;
  return `${e.constructor.name}:${e.message}`;
}

function run(c: any): any {
  const t = c.type;
  if (t === 'key_agg') {
    const pubs = c.pubkeys.map(un);
    const tweaks = (c.tweaks || []).map(un);
    const isX = c.is_xonly || [];
    const ctx = musig2.keyAggregate(pubs, tweaks, isX);
    return {
      aggpk: hx(musig2.keyAggExport(ctx)),
      gacc: ctx.gAcc.toString(),
      tacc: ctx.tweakAcc.toString(),
      compressed: hx(ctx.aggPublicKey.toBytes(true)),
    };
  }
  if (t === 'nonce_gen') {
    const rand = un(c.rand);
    const sk = c.sk ? un(c.sk) : undefined;
    const pk = un(c.pk);
    const aggpk = c.aggpk ? un(c.aggpk) : undefined;
    const msg = c.msg != null ? un(c.msg) : undefined;
    const extra = c.extra_in ? un(c.extra_in) : undefined;
    const n = musig2.nonceGen(pk, sk, aggpk as any, msg as any, extra as any, rand);
    return { secnonce: hx(n.secret), pubnonce: hx(n.public) };
  }
  if (t === 'nonce_agg') {
    return { aggnonce: hx(musig2.nonceAggregate(c.pubnonces.map(un))) };
  }
  if (t === 'session_values') {
    // Reach into Session internals to compare b/e/R/Q with reference get_session_values.
    const s: any = new musig2.Session(
      un(c.aggnonce),
      c.pubkeys.map(un),
      un(c.msg),
      (c.tweaks || []).map(un),
      c.is_xonly || []
    );
    return {
      b: s.b.toString(),
      e: s.e.toString(),
      R: hx(s.R.toBytes(true)),
      gacc: s.gAcc.toString(),
      tacc: s.tweakAcc.toString(),
      Q: hx(s.Q.toBytes(true)),
    };
  }
  if (t === 'sign') {
    const sec = un(c.secnonce);
    const s = new musig2.Session(
      un(c.aggnonce),
      c.pubkeys.map(un),
      un(c.msg),
      (c.tweaks || []).map(un),
      c.is_xonly || []
    );
    const psig = s.sign(sec, un(c.sk));
    return { psig: hx(psig), secnonce_after: hx(sec) };
  }
  if (t === 'det_sign') {
    const r = musig2.deterministicSign(
      un(c.sk),
      un(c.aggothernonce),
      c.pubkeys.map(un),
      un(c.msg),
      (c.tweaks || []).map(un),
      c.is_xonly || [],
      c.rand ? un(c.rand) : undefined
    );
    return { pubnonce: hx(r.publicNonce), psig: hx(r.partialSig) };
  }
  if (t === 'sig_agg') {
    const s = new musig2.Session(
      un(c.aggnonce),
      c.pubkeys.map(un),
      un(c.msg),
      (c.tweaks || []).map(un),
      c.is_xonly || []
    );
    return { sig: hx(s.partialSigAgg(c.psigs.map(un))) };
  }
  if (t === 'verify') {
    const s = new musig2.Session(
      musig2.nonceAggregate(c.pubnonces.map(un)),
      c.pubkeys.map(un),
      un(c.msg),
      (c.tweaks || []).map(un),
      c.is_xonly || []
    );
    return { verify: s.partialSigVerify(un(c.psig), c.pubnonces.map(un), c.index) };
  }
  throw new Error('unknown case type ' + t);
}

const chunks: Buffer[] = [];
process.stdin.on('data', (d) => chunks.push(d));
process.stdin.on('end', () => {
  const cases = JSON.parse(Buffer.concat(chunks).toString());
  const out = cases.map((c: any) => {
    try {
      return { ok: run(c) };
    } catch (e: any) {
      return { err: errString(e) };
    }
  });
  process.stdout.write(JSON.stringify(out));
});

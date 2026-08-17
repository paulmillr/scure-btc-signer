# MuSig2 secnonce single-use contract: copied/persisted secnonces bypass in-place zeroization, enabling full key extraction

- **Severity:** Medium — full MuSig2 key extraction by a co-signer; needs the victim to persist/copy the secnonce and reuse it in 3 distinct sessions
- **Confidence:** High (deterministic local reproducer; key extraction verified end-to-end)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0, tip of upstream `main` at review time)
- **Affected file:** `src/musig2.ts`
- **PoC:** `2026-08-05-musig2-secnonce-single-use-contract/` (same date-and-slug identifier)

## Summary

`Session.sign()` enforces BIP327's "never sign twice with the same secnonce" rule
only by zeroing the first 64 bytes of the caller-supplied `Uint8Array` **in
place** (`src/musig2.ts:615`). The secret nonce itself carries no session
binding of any kind beyond the signer pubkey — no aggregate key, no message,
no aggnonce, no session id, and no spent-marker exists anywhere in the
library. Any copy of the secnonce made before `sign()` runs (explicit
`structuredClone`/`slice`, JSON/DB persistence between MuSig2 round 1 and
round 2, crash recovery, hardware/VM snapshot) survives the zeroization and
can be used to sign again in a **different** session. Three partial signatures
produced with the same `(k1, k2)` under three distinct `(b, e)` give three
independent linear equations mod n; the attacker (a malicious co-signer or
coordinator) solves for `k1, k2, d` and recovers the victim's secret key in
closed form. The PoC demonstrates exact key recovery plus recovery of the
nonce scalars themselves.

BIP327 requires stateful signers to store the secnonce between the two
signing rounds, so persistence — the exact pattern that defeats the
zeroization — is the normal integration shape, not an exotic one. The code
comment above the zeroization already flags the design ("this was in the
reference implementation, but feels very broken. Modifying input arguments is
pretty bad.", `src/musig2.ts:613-614`), and BIP327 itself recommends the
stronger pattern this library does not offer: "implementations may choose to
hide the secnonce in internal state without exposing it in an API explicitly,
e.g., in an effort to prevent callers from reusing a secnonce accidentally"
(BIP327, footnote on secnonce storage).

## Root cause and violated invariant

Invariant (from the review skills): a secret nonce must be unique,
unpredictable, **single-use, and destroyed or irreversibly marked spent
before a signature leaves the signer**; the session must bind the nonce to
the transcript (aggregate key, message, aggregate nonce).

Relevant code:

- `src/musig2.ts:115-120` — `SecretNonce` coder: `k1 || k2 || publicKey`
  (97 bytes). No session context fields.
- `src/musig2.ts:605-641` — `Session.sign(secretNonce, secret, fastSign)`:
  - `:609` decodes `k1, k2, originalPk` from the caller's buffer;
  - `:615` `secretNonce.fill(0, 0, 64)` — the only reuse mitigation, applied
    to the caller's buffer instance only;
  - `:616-617` `wrong k1`/`wrong k2` — fail-fast once the *same buffer* is
    reused (works as intended);
  - `:624` `Public key does not match nonceGen argument` — the **only**
    binding check; it ties the secnonce to a *key*, never to a *session*;
  - `:629` `s = k1 + b*k2 + e*a*d` with session-cached `b, e` — nothing here
    checks that this secnonce was generated for *this* `(aggnonce, Q, msg)`.
- `src/musig2.ts:384-413` — `nonceGen` mixes `aggpk`/`msg` into the nonce
  hash when provided, but `sign()` has no way to verify that binding after
  the fact; the 97-byte encoding discards it.

Because `Session.sign` is synchronous and zeroization happens immediately
after decode, reuse of the *same buffer instance* fails safely
(verified). Every other representation of the same secnonce remains fully
usable, and `sign()` cannot distinguish "the nonce generated for this
session" from "a nonce generated earlier for some other session".

## Attacker model, prerequisites, attacker-controlled path

- Attacker: malicious MuSig2 co-signer or coordinator. Controls session
  scheduling (start/abort/retry), messages, own nonces, and can observe all
  public nonces and partial signatures.
- Victim: runs this library with a real secret key and keeps the secnonce in
  any form that survives `fill(0)` — e.g., persists it to a database between
  round 1 (nonceGen) and round 2 (sign), or clones process state.
- Path: coordinator runs session 1 to completion (or aborts after obtaining
  the victim's pubnonce and starts a "new" session), then triggers two more
  sessions with fresh messages/nonces. On each, the victim reloads the
  persisted 97-byte secnonce and signs. Each signature is honestly computed
  and passes every library check (including the in-`sign` self-verification,
  which only checks the signer's own nonce limbs, `src/musig2.ts:632-639`).

## Extraction math (verified by PoC)

Per session `j`, the partial signature is

```
s_j = p_j*k1 + p_j*b_j*k2 + e_j*a*d   (mod n)
```

where `p_j = ±1` is the known `has_even_y(R_j)` parity adjustment applied by
`sign()` (`src/musig2.ts:618-619`), `b_j, e_j` are public session hashes, and
`a` is the victim's public key-aggregation coefficient. Unknowns: `k1, k2,
d`. Two sessions leave one degree of freedom (2 equations, 3 unknowns — so
the sometimes-quoted "two reused partial signatures" intuition from
single-nonce ECDSA does **not** suffice for MuSig2's two-limb nonce);
**three** sessions yield a 3×3 linear system over `Z_n`, solved by Gaussian
elimination. Finally `d' = d · (g·gacc)⁻¹` recovers the raw secret key.

## Observed output (PoC `run.log`)

```
== MuSig2 secnonce reuse -> key extraction ==
victim secret key    : bc2a8131c2a83a38ba08c70a5fe2ffbf93ece3b7dc42adc52d13650e0d1736e3
extracted secret key : bc2a8131c2a83a38ba08c70a5fe2ffbf93ece3b7dc42adc52d13650e0d1736e3
MATCH                : true
sanity: extracted key reproduces victim pubkey: true
recovered k1,k2 match persisted secnonce limbs: true

== negative evidence ==
(a) second sign with same zeroized buffer throws: RangeError
(a) zeroization visible: first 64 bytes all zero: true | pk bytes 64..97 intact: true
(b) same-session copy reuse -> identical psig (no new info): true
```

Negative evidence (also in the PoC): reusing the *same* buffer fails fast at
decode; zeroization leaves the pubkey tail intact as BIP327 intends; reuse
inside the *same* session produces a byte-identical psig (same equation, no
leak) — exploitation strictly requires distinct sessions.

## Impact

Full extraction of the victim's MuSig2 individual secret key. For a 2-of-2
(or m-of-n with the attacker controlling the remaining keys) collaborative
custody wallet — the stated downstream consumer of this module — this is
total loss of the shared funding output(s), and the attacker can also forge
the victim's partial signature in any future session with any participant
set. Exploitation is silent: every victim signature is individually valid.

## Conformance note (why this is a contract vulnerability, not a BIP327 deviation)

The implementation matches BIP327 (bips commit
`e7263a4cfe500c89e4269889244606953691ca33`, vectors byte-identical; 25/25
project vector tests pass; 752/752 differential cases against
`reference.py` match). BIP327's Sign section says: "The Sign algorithm must
**not** be executed twice with the same secnonce", and lists the 64-byte
overwrite as an optional ("may") mitigation. The library implements exactly
that MAY and nothing more, exposes the raw 97-byte secnonce across its API,
and its own `sign()` jsdoc (`src/musig2.ts:598`) says only "it is zeroed
after use" — which affirmatively suggests reuse is impossible, while the
BIP327 IMPORTANT warning about double-signing is not repeated anywhere in
the module's documentation. The contract as documented is therefore
*misleadingly weak*: it protects exactly one buffer instance, while the
protocol's normal stateful flow (generate in round 1, store, sign in round
2) pushes callers toward copies the protection cannot reach.

## Remediation

1. **Stop exposing raw secnonces (preferred).** Offer an opaque per-session
   object (class/closure) returned by `nonceGen` that owns `k1, k2`
   internally, is consumed by `sign()` (including on exception), and is never
   serializable. BIP327 explicitly endorses this ("implementations may choose
   to hide the secnonce in internal state"). `deterministicSign`
   (`src/musig2.ts:748-778`) already proves the library can keep the secnonce
   internal for stateless flows.
2. **If raw bytes stay for flexibility, document the real contract** at
   `nonceGen`/`Session.sign`: the secnonce must never be copied, serialized,
   or reused across sessions; in-place zeroization protects only the buffer
   passed in; reuse in 3 sessions leaks the secret key. Repeat BIP327's
   IMPORTANT warning verbatim in the jsdoc.
3. **Defense in depth:** zeroize all 97 bytes (not 64) and, for callers that
   must persist, provide a caller-supplied session-id input mixed into the
   nonce hash *and* stored in the secnonce wrapper for a hard sign-time
   equality check (BIP327 permits any internal secnonce representation).
4. Keep the existing fail-closed property (nonce consumed even when later
   checks throw, `src/musig2.ts:615` runs before `:616-624`) — it is correct.

## References

- BIP327 (MuSig2), bitcoin/bips @ `e7263a4cfe500c89e4269889244606953691ca33`:
  Signing ("must not be executed twice with the same secnonce"), Nonce
  Generation (stateful signer storage requirement), secnonce footnote
  (hide-in-internal-state recommendation).
- `src/musig2.ts:115-120, 384-413, 605-641` (reviewed commit).
- PoC: `poc-secnonce-reuse.ts`, `run.log`, `README.md` in the PoC directory.

## Independent validation qualification (2026-08-10)

The PoC recovered the victim scalar exactly from three sessions using copied/persisted nonce bytes. Reusing the same buffer fails because it is zeroized. BIP327 explicitly says `Sign` must never execute twice with the same secnonce and permits overwriting the secnonce input; therefore the key-recovery consequence is real, but the trigger is a violation of the protocol's caller contract. Present this as a conditional integration/API-safety hazard, not as a MuSig2 protocol-conformance failure.

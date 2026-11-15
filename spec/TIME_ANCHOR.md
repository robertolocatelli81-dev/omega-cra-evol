# The time anchor of a long-term seal record — `cra-lta-time-anchor/1` (2026-11-15)

Status: normative for `omega_cra_evol.longterm` (`LongTermEvidence.seal`, `cra seal`) and `omega_cra_evol.time_anchor`
from the release after 0.11.1. Written before the code (15/11/2026). It defines what the RFC 3161 token of a seal record
stamps, which time the record carries, and how a verifier checks both against a TSA it pins. Until now no token was
verified by this package: `LongTermEvidence.verify` called a `timestamp_trust_fn` the caller had to write, and the
package shipped none (its own tests passed `lambda r: True`, which accepts anything, the string `not base64!` included).

## 1. Scope

A seal (`format: "CRA-LTA-1"`, unchanged) is a chain of records over one evidence digest `D` (64 lowercase hex,
SHA3-256 of the pack). This text applies to the records with `ts_source: "rfc3161"`. `asserted` records carry no token;
`ots` tokens keep the shape check of 0.9.0 and no binding is defined for them here.

## 2. What the token stamps

Record `i` of a chain carries `"anchor": "cra-lta-time-anchor/1"`, and its token's `TSTInfo.messageImprint` is

    hashedMessage = H( "cra-lta-time-anchor/1\n" || canon([D, records[0..i-1], own_i]) )

- `canon` is the canonical JSON of `longterm.py` (`json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=True)`), encoded as UTF-8 (ASCII by construction);
- `records[0..i-1]` are the previous records of the chain, whole (their tokens and signatures included): a renewal's
  token says that the whole chain before it existed at its time, the point of a renewal (RFC 4998 §5.2, Hash-Tree
  Renewal, hashes the data objects together with all previous Archive Timestamp Chains and timestamps that again);
- `own_i` is the object of the record's own fields that exist before the token is requested: `alg`, `anchor`,
  `ephemeral_key`, `hash`, `pub`, `rehash`, `ts_source` — not `t` (taken from the token, §3), `token_b64`, `token_sha3`
  (the token itself) or `sig` (made after the token: the record's signature covers the token);
- `H` is SHA-256 (OID 2.16.840.1.101.3.4.2.1) or SHA3-256 (2.16.840.1.101.3.4.2.8), the token's `hashAlgorithm`; any
  other algorithm is refused. SHA-256 is admitted because public TSAs refuse SHA3-256: on 15/11/2026 freetsa.org and
  timestamp.digicert.com answered `Rejected` to a SHA3-256 query and `Granted` to a SHA-256 one.

The domain line makes the imprint useless as the digest of anything else this package hashes.

## 3. The time

The record's `t` is the token's `genTime`, as seconds since 1970-01-01T00:00:00Z: the calendar seconds of
`YYYYMMDDhhmmss` (UTC), then the fraction digits of `genTime` if any, read as the decimal string `"<seconds>.<fraction>"`
and stored as `repr(float(...))` (the representation `longterm.py` uses for every `t`). A record with this anchor whose
`t` differs from that value is refused (§5). `genTime` must be a GeneralizedTime of RFC 3161 §2.4.2 (UTC, `Z`, no
trailing zero in a fraction).

## 4. Sealing

`LongTermEvidence.seal(signer, t, ts_source="rfc3161", token_b64=...)`:

- the token's shape is checked as since 0.9.0 (a TimeStampResp granted, or a TimeStampToken, with an id-ct-TSTInfo);
- its imprint must be §2's for this record and this signer, else `TokenRefused` naming the imprint expected;
- `t` may be `None` (taken from `genTime`) or equal to §3's value; any other `t` is refused;
- the record gets `"anchor": "cra-lta-time-anchor/1"`.

`LongTermEvidence.anchor_imprint(signer, hash_alg, stronger_digest, tsa_hash)` gives the hex of §2 before the token is
requested; `cra seal --print-imprint` prints it (it needs the sealing key, `--tip-key`: an ephemeral key is made at seal
time and cannot be known in advance).

**Changed:** a `rfc3161` token whose imprint is the bare digest `D` — the only shape `cra seal` accepted from 0.9.0 to
0.11.1 — is refused at seal from this version: it says that `D` existed, not that this record or this chain did, and a
verifier of §5 refuses it (`digest_only_binding`). Seals written before keep verifying as before (§6).

## 5. Verification

`omega_cra_evol.time_anchor.make_timestamp_trust_fn(lte, tsa_certs)` returns the `timestamp_trust_fn` that
`LongTermEvidence.verify` calls on each record. `tsa_certs` are the TSA certificates the verifier pins (paths or PEM/DER
bytes: the TSA certificate or a CA above it); without one the function cannot be made (a token checked against the
certificate it carries proves nothing about who issued it). For each record, the first check that fails gives the closed
reason, written to `fn.log`, and the function returns `False`:

1. `record_not_in_chain` — the record is not one of `lte.records`;
2. `ts_source_not_rfc3161` — `asserted` or `ots`: not attested by this function;
3. `digest_only_binding` — a `rfc3161` record without `anchor` (sealed 0.9.0–0.11.1); `anchor_unknown` — another value;
4. `token_missing`, `token_not_base64`, `token_malformed` — no token, not strict base64, not an RFC 3161 token by the
   shape check of 0.9.0 or with a `genTime` outside §3's form;
5. `imprint_mismatch` — the token's hash algorithm is not one of §2's, or its hashedMessage is not §2's for this record;
6. `t_not_gen_time` — `t` is not §3's value;
7. `signature_invalid` — the token's CMS signature does not verify (`openssl cms -verify -noverify`, with the pinned
   certificates as candidate signers);
8. `not_issued_by_pinned_tsa` — `openssl ts -verify` against the pinned certificates (`-partial_chain`, validity at
   `genTime` with `-attime`) does not answer `Verification: OK`.

The function returns `True` only when all eight pass. openssl absent, or present and not able to run, ended by a
signal or not answering, is not a refusal: the function raises `TimeAnchorNotRun` (an `OSError`), and no verdict is
given. `verify` reports `temporal_trust: "verified"` only when the function accepted every record (unchanged).

## 6. Compatibility

Nothing changes for a verifier that injects no function: `temporal_trust` stays `ASSUMED …` as before, and every other
check of a seal is unchanged. A seal written by 0.9.0–0.11.1 with `rfc3161` tokens is refused by §5 at step 3 with
`digest_only_binding`; before this version no function of this package could say anything about it. The format name
`CRA-LTA-1` does not change: a reader of 0.11.1 reads a record with `anchor` as before (the field is one more signed
own field).

## 7. Not covered

Revocation of the TSA certificate (no CRL or OCSP is fetched); the TSA's `accuracy`; trusted lists; renewal of the
TSA's own trust after its certificate expires (a later record of the chain, made before that, is the renewal). The
verifier reads `genTime`; it does not compare it with a clock.

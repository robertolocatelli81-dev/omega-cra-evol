# The time anchor of a long-term seal record — `cra-lta-time-anchor/1` (2026-11-15)

Status: normative for `omega_cra_evol.longterm` (`LongTermEvidence.seal`, `cra seal`) and `omega_cra_evol.time_anchor`
from 0.12.0. Written before the code (15/11/2026); §5 steps 7–8 and §7 amended before the code of 0.13.0 (17/11/2026, §8). It defines what the RFC 3161 token of a seal record
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
   `unknown_field` — a field outside the closed list `alg`, `anchor`, `ephemeral_key`, `hash`, `pub`, `rehash`, `sig`,
   `t`, `token_b64`, `token_sha3`, `ts_source` (a field the token does not stamp is never accepted with the record);
4. `token_missing`, `token_not_base64`, `token_malformed` — no token, not strict base64, not an RFC 3161 token by the
   shape check of 0.9.0 or with a `genTime` outside §3's form;
5. `imprint_mismatch` — the token's hash algorithm is not one of §2's, or its hashedMessage is not §2's for this record;
6. `t_not_gen_time` — `t` is not the string §3 defines (`repr` of the float of genTime: `" 1.0"`, `"+1.0"`, `"1"` for
   `"1.0"` are refused, though `float()` reads them as the same number);
7. `signature_invalid` — the token's CMS signature does not verify (`openssl cms -verify -noverify`, with the pinned
   certificates as candidate signers; the certificate it verified with is the signer certificate of step 8);
8. `not_issued_by_pinned_tsa` — the token is not established under the pinned certificates. How depends on how its
   SignerInfo names the signer (`sid`, RFC 5652 §5.3; both forms are allowed):
   - **issuerAndSerialNumber**: `openssl ts -verify` against the pinned certificates (`-partial_chain`, the pinned
     certificates also as `-untrusted`, validity at `genTime` with `-attime`) does not answer `Verification: OK`.
   - **subjectKeyIdentifier** (from 0.13.0): openssl's TS code reads the token as PKCS #7, whose SignerInfo has only the
     first form, and refuses this one with an ASN.1 error, so 0.12.0 refused a valid token of this form. The checks
     `ts -verify` makes are made one by one, as cryptovalid-opencore's SPEC §11 step 7 makes them (v0.10, same
     author): the token has exactly one SignerInfo, with signed attributes; (a) a signed attribute signingCertificate
     (RFC 2634 §5.4, SHA-1) or signingCertificateV2 (RFC 5035; its `hashAlgorithm`, SHA-256 when absent, with no
     parameter or a NULL one), at least one present, each present once with exactly one value holding exactly one
     ESSCertID (more than one is not evaluated here and fails) whose `certHash` is the hash of the signer
     certificate and whose `issuerSerial`, when present, is exactly one directoryName equal to the certificate's issuer
     and the certificate's serial number (compared as integers); (b) the TSTInfo `tsa` field, when present: one
     GeneralName, a directoryName equal to the signer's subject, or equal to one of the names of the signer's
     subjectAltName (a directoryName compared as a name, another type with the same type and the same bytes, as
     OpenSSL's `GENERAL_NAME_cmp`); (c) `openssl verify -purpose timestampsign -partial_chain -attime <genTime>
     -CAfile <pinned> -no-CApath -no-CAstore -untrusted <pinned and the token's certificates> <signer certificate>`
     exits 0: the extended key usage timeStamping as OpenSSL's purpose reads it, the chain to a pinned certificate with
     OpenSSL's chain building (a pinned leaf does not end it: the CA the token carries above it is checked too), the
     validity at `genTime`, and no certificate of the system store (`SSL_CERT_DIR`, the default directory or store)
     taking part. Two names are equal as OpenSSL's `X509_NAME_cmp` compares them: each attribute value of a string type
     (UTF8String, PrintableString, IA5String, VisibleString, T61String read as Latin-1, BMPString, UniversalString) is
     turned into UTF-8, white space at both ends removed, each run of white space made one space, ASCII letters
     lowercased; values of other types are compared as encoded; the same RDNs in the same order, each RDN the same
     attributes in any order. An openssl that rejects one of these options as unknown (before 3.0, or not OpenSSL) did
     not run the check: `TimeAnchorNotRun`, no verdict.

9. `token_sha3_mismatch` — `token_sha3` is absent or not the SHA3-256 hex of the `token_b64` string.

The function returns `True` only when all nine pass. The pinned certificates are checked before any record: each
PEM block or DER item must have the shape of an X.509 certificate (RFC 5280 §4.1: a SEQUENCE of two SEQUENCEs and a BIT
STRING), and a path must be a readable regular file; otherwise `ValueError` and no function is made (a pin openssl
cannot load would refuse every token as `signature_invalid`). openssl absent, or present and not able to run, ended by a
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

Qualified electronic time stamps: under Commission Implementing Regulation (EU) 2025/1929 (OJ L, 30.9.2025, in force
from 20 October 2025; Annex, adaptation of ETSI EN 319 422 clause 9.1, "Regulation compliance statement"), a token the
TSA declares a qualified electronic time stamp contains one qcStatements extension (RFC 3739 §3.2.6), not critical,
with one statement `esi4-qtstStatement-1`; whether the TSA holds the qualified status is read on the EU trusted lists.
This verifier reads neither: it never reports a token as qualified, and a token with that statement is checked as any
other (read on CELLAR on 17/11/2026, sha256 of the Official Journal XHTML `835e781cf749d866…`).

## 8. Amendment of 17/11/2026 (0.13.0)

Written before the code. §5 step 8 gains the subjectKeyIdentifier form; step 7 names the signer certificate step 8
reads. A record whose token names its signer by issuerAndSerialNumber is checked exactly as in 0.12.0. A record whose
token names it by subjectKeyIdentifier was always refused by 0.12.0 (`not_issued_by_pinned_tsa`, the ASN.1 error of
`ts -verify`); from 0.13.0 it is accepted when (a), (b) and (c) pass. This changes verdicts, hence a minor version. The
format, the anchor name `cra-lta-time-anchor/1` and the closed list of reasons do not change.

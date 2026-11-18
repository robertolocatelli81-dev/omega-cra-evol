# SPDX-License-Identifier: AGPL-3.0-or-later
"""A `timestamp_trust_fn` for LongTermEvidence.verify that can refuse (spec/TIME_ANCHOR.md §5, cra-lta-time-anchor/1).

Until this module the package shipped none: `verify` without one says `temporal_trust: ASSUMED`, and the package's own
tests injected `lambda r: True`, under which a record whose "token" is the string `not base64!` was verified. This
function checks, for each record, that its RFC 3161 token stamps that record (the evidence digest, every previous record
and the record's own fields), that the record's time is the token's genTime, that the token's signature verifies, and
that the TSA is one the verifier pins (openssl `cms -verify` and `ts -verify`, as cryptovalid-opencore's SPEC §11 does
for its tokens; for a signer named by subjectKeyIdentifier, which `ts -verify` cannot read, the same checks one by one
and `openssl verify`, spec §5 step 8 as amended for 0.13.0). Proposed by Athena's review of 15/11/2026 (its prototype
p5_timestamp_trust.py), rewritten here.

It returns a bool (the interface of longterm.verify); the closed reason of each answer is appended to `fn.log`. An
openssl that is absent or cannot run is not a refusal: TimeAnchorNotRun is raised and no verdict is given."""
from __future__ import annotations

# The names other code may import from this module (provisional tier of API.md). tests/test_api_surface keeps the list.
__all__ = ["REASONS", "TimeAnchorNotRun", "make_timestamp_trust_fn"]

import base64
import binascii
import hashlib
import os
import shutil
import subprocess  # nosec B404 - openssl only, fixed arguments, no shell
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .longterm import ANCHOR, LongTermEvidence
from .rfc3161_token import (OID_SHA256, OID_SHA3_256, TokenRefused, _children, _oid, gen_time_seconds,
                            rfc3161_tstinfo, timestamp_token_der)

REASONS = ("record_not_in_chain", "ts_source_not_rfc3161", "digest_only_binding", "anchor_unknown", "unknown_field",
           "token_missing", "token_not_base64", "token_malformed", "imprint_mismatch", "t_not_gen_time",
           "signature_invalid", "not_issued_by_pinned_tsa", "token_sha3_mismatch",
           "signer_certificate_absent")   # spec §5 step 7, 0.13.0 (18/11/2026): not evaluated, logged with "ok": None
# spec/TIME_ANCHOR.md §2, §5 step 3: the fields an anchored record may carry (closed: anything else is refused)
_RECORD_FIELDS = frozenset(("alg", "anchor", "ephemeral_key", "hash", "pub", "rehash", "sig", "t", "token_b64", "token_sha3",
                           "ts_source"))
_HASH_NAMES = {OID_SHA256: "sha256", OID_SHA3_256: "sha3-256"}


class TimeAnchorNotRun(OSError):
    """openssl absent, not startable, ended by a signal, or not answering: the check did not run (not a refusal)."""


def _pins_pem(tsa_certs: Sequence[Union[str, bytes]]) -> bytes:
    """The pinned certificates as one PEM bundle; PEM or DER, given as paths or bytes. ValueError if none is usable."""
    if isinstance(tsa_certs, (str, bytes, bytearray)) or not isinstance(tsa_certs, (list, tuple)) or not tsa_certs:
        raise ValueError("tsa_certs: a non-empty list of TSA certificates (paths or PEM/DER bytes)")
    out = b""
    for c in tsa_certs:
        if isinstance(c, str):
            if not os.path.isfile(c):
                raise ValueError(f"tsa_certs: {c!r} is not a readable file")
            try:
                from .ledger import read_regular       # decided on the open descriptor: a swap after isfile() is refused
                c = read_regular(c)
            except OSError as e:   # NEMESIS 15/11/2026: an unreadable file was a PermissionError (a traceback in cra seal)
                raise ValueError(f"tsa_certs: cannot read {c!r}: {e.strerror or e}") from None
        if not isinstance(c, (bytes, bytearray)) or not c:
            raise ValueError("tsa_certs: an entry is neither a path nor certificate bytes")
        c = bytes(c)
        if b"-----BEGIN CERTIFICATE-----" in c:
            blocks = c.split(b"-----BEGIN CERTIFICATE-----")[1:]
            if not all(_is_certificate_der(_pem_block_der(bl)) for bl in blocks):
                raise ValueError("tsa_certs: a PEM block is not a certificate")
            out += c if c.endswith(b"\n") else c + b"\n"
        elif _is_certificate_der(c):
            b64 = base64.b64encode(c)
            out += b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + \
                b"\n-----END CERTIFICATE-----\n"
        else:
            raise ValueError("tsa_certs: an entry is not a PEM or DER certificate")
    return out


def _pem_block_der(block: bytes) -> bytes:
    """The DER of one PEM certificate block (the bytes after its BEGIN line), or b"" if it does not decode strictly."""
    if b"-----END CERTIFICATE-----" not in block:
        return b""
    try:
        return base64.b64decode(b"".join(block.split(b"-----END CERTIFICATE-----", 1)[0].split()), validate=True)
    except (binascii.Error, ValueError):
        return b""


def _is_certificate_der(der: bytes) -> bool:
    """RFC 5280 §4.1 shape: SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING } filling the bytes exactly (a shape check; openssl
    reads the certificate). NEMESIS 15/11/2026: a pin that only began with 0x30 was accepted, openssl could not load it,
    and every token was refused as `signature_invalid` (a fault of the pin reported as a fault of the token)."""
    def tlv(i):
        if i + 2 > len(der):
            return None
        tag, n, j = der[i], der[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 4 or j + k > len(der):
                return None
            n, j = int.from_bytes(der[j:j + k], "big"), j + k
        return (tag, j, j + n) if j + n <= len(der) else None
    top = tlv(0)
    if top is None or top[0] != 0x30 or top[2] != len(der):
        return False
    i, tags = top[1], []
    while i < top[2]:
        el = tlv(i)
        if el is None:
            return False
        tags.append(el[0])
        i = el[2]
    return tags == [0x30, 0x30, 0x03]


def _openssl(args: List[str], timeout: float) -> subprocess.CompletedProcess:
    exe = shutil.which("openssl")
    if not exe:
        raise TimeAnchorNotRun("openssl absent: the token's signature and TSA cannot be checked here")
    try:
        p = subprocess.run([exe] + args, capture_output=True, timeout=timeout)  # nosec B603 - fixed args, no shell
    except subprocess.TimeoutExpired:
        raise TimeAnchorNotRun(f"openssl did not answer within {timeout} s") from None
    except OSError as e:
        raise TimeAnchorNotRun(f"cannot run openssl here: {e}") from None
    if p.returncode < 0:
        raise TimeAnchorNotRun(f"openssl ended by signal {-p.returncode}")
    return p


# ── spec/TIME_ANCHOR.md §5 step 8, a signer named by subjectKeyIdentifier (0.13.0). Ported from cryptovalid-opencore's
# cryptovalid_tsa.py (SPEC §11 step 7, v0.10, same author, AGPL-3.0-or-later), on this package's DER reader.
_OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"      # RFC 2634 §5.4, ESSCertID with SHA-1
_OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"   # RFC 5035, ESSCertIDv2
_OID_SUBJECT_ALT_NAME = "2.5.29.17"
_ESS_HASHES = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
               "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512",
               "2.16.840.1.101.3.4.2.8": "sha3_256", "2.16.840.1.101.3.4.2.9": "sha3_384",
               "2.16.840.1.101.3.4.2.10": "sha3_512"}


def _items(buf: bytes) -> List[tuple]:
    """every DER element of `buf`, in order: [(tag, value)] (TokenRefused unless they fill it exactly)"""
    return [(t, bytes(buf[a:b])) for t, a, b in _children(buf, 0, len(buf))]


def _one(buf: bytes, tag: int) -> bytes:
    it = _items(buf)
    if len(it) != 1 or it[0][0] != tag:
        raise TokenRefused(f"expected one element of tag 0x{tag:02x}")
    return it[0][1]


def _tlv(tag: int, v: bytes) -> bytes:
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def _oid_of(v: bytes) -> str:
    """an OBJECT IDENTIFIER's value; an arc not in minimal form (a leading 0x80) is refused"""
    if any(b == 0x80 and (i == 0 or not v[i - 1] & 0x80) for i, b in enumerate(v)):
        raise TokenRefused("OBJECT IDENTIFIER arc not in minimal form")
    b = _tlv(0x06, v)
    return _oid(b, (0x06, len(b) - len(v), len(b)))


# OpenSSL's canonical form of a Name (crypto/x509/x_name.c x509_name_canon, asn1_string_canon): what X509_NAME_cmp
# compares, and what `openssl ts -verify` uses for the tsa field and the ESS issuerSerial (spec §5 step 8)
_CANON_STRING = {0x0C: "utf-8", 0x13: "latin-1", 0x14: "latin-1", 0x16: "latin-1", 0x1A: "latin-1",
                 0x1E: "utf-16-be", 0x1C: "utf-32-be"}
_C_SPACE = b" \t\n\v\f\r"


def _canon_value(tag: int, value: bytes) -> tuple:
    """a string type: UTF-8, white space trimmed and runs made one space, ASCII letters lowercased; other types as encoded"""
    enc = _CANON_STRING.get(tag)
    if enc is None:
        return ("raw", tag, value)
    b = value.decode(enc).encode("utf-8")                 # ValueError when not decodable: the names are not equal
    b = b.strip(_C_SPACE)
    out, i = bytearray(), 0
    while i < len(b):
        c = b[i]
        if c >= 0x80:
            out.append(c)
            i += 1
        elif c in _C_SPACE:
            out.append(0x20)
            while i < len(b) and b[i] in _C_SPACE:
                i += 1
        else:
            out.append(c + 32 if 0x41 <= c <= 0x5A else c)
            i += 1
    return ("str", bytes(out))


def _name_canon(name_tlv: bytes) -> tuple:
    """the canonical form of a DER Name (SEQUENCE OF RDN): RDNs in order, each a sorted tuple of (OID, value)"""
    rdns = []
    for t, rdn in _items(_one(name_tlv, 0x30)):
        if t != 0x31:
            raise TokenRefused("Name: an RDN is not a SET")
        attrs = []
        for t2, atv in _items(rdn):
            a = _items(atv)
            if t2 != 0x30 or len(a) != 2 or a[0][0] != 0x06:
                raise TokenRefused("Name: AttributeTypeAndValue")
            attrs.append((a[0][1], _canon_value(a[1][0], a[1][1])))
        rdns.append(tuple(sorted(attrs, key=repr)))
    return tuple(rdns)


def _names_equal(a_tlv: bytes, b_tlv: bytes) -> bool:
    try:
        return _name_canon(a_tlv) == _name_canon(b_tlv)
    except (TokenRefused, ValueError):
        return False


def _general_names_equal(a: tuple, b: tuple) -> bool:
    """GENERAL_NAME_cmp: the same type; a directoryName compared as a Name, any other type by its bytes"""
    if a[0] != b[0]:
        return False
    return _names_equal(a[1], b[1]) if a[0] == 0xA4 else a[1] == b[1]


def _signed_data(token_der: bytes) -> List[tuple]:
    ci = _items(_one(token_der, 0x30))
    if len(ci) != 2 or ci[1][0] != 0xA0:
        raise TokenRefused("not a ContentInfo with [0] content")
    return _items(_one(ci[1][1], 0x30))


def _signer_infos(token_der: bytes) -> List[tuple]:
    """the SignerInfos of the token's SignedData (signerInfos is its last element, a SET)"""
    sd = _signed_data(token_der)
    if sd[-1][0] != 0x31:
        raise TokenRefused("SignedData: signerInfos is not a SET")
    return _items(sd[-1][1])


def _signer_named_by_key_id(token_der: bytes) -> bool:
    """spec §5 step 8: the SignerInfo's sid is [0] subjectKeyIdentifier (RFC 5652 §5.3), not issuerAndSerialNumber"""
    try:
        sis = _signer_infos(token_der)
        return any(_items(v)[1][0] == 0x80 for t, v in sis if t == 0x30)
    except (TokenRefused, IndexError):
        return False


def _token_certificates(token_der: bytes) -> List[bytes]:
    """the DER of each certificate in the SignedData `[0] certificates` of the token"""
    try:
        return [_tlv(t, v) for tag, val in _signed_data(token_der)[3:] if tag == 0xA0 for t, v in _items(val) if t == 0x30]
    except (TokenRefused, IndexError):
        return []


def _policies_shape(el: tuple) -> bool:
    """ESS `policies` (RFC 2634 §5.4.1): SEQUENCE OF PolicyInformation, each a SEQUENCE that starts with an OID"""
    if el[0] != 0x30:
        return False
    for t, v in _items(el[1]):
        pi = _items(v)
        if t != 0x30 or not pi or pi[0][0] != 0x06:
            return False
    return True


def _pem(der: bytes) -> bytes:
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


def _pem_ders(pem: bytes) -> List[bytes]:
    return [_pem_block_der(bl) for bl in pem.split(b"-----BEGIN CERTIFICATE-----")[1:]]


def _issuer_serial(der: bytes) -> tuple:
    """(issuer Name TLV, serial number as an integer) of a DER certificate"""
    tbs = _items(_items(_one(der, 0x30))[0][1])
    k = 1 if tbs[0][0] == 0xA0 else 0
    if tbs[k][0] != 0x02 or tbs[k + 2][0] != 0x30:
        raise TokenRefused("certificate serialNumber or issuer not read")
    return _tlv(0x30, tbs[k + 2][1]), int.from_bytes(tbs[k][1], "big", signed=True)


def _ess_names(isr: tuple, der: bytes) -> bool:
    issuer, serial = _issuer_serial(der)
    return _names_equal(isr[0], issuer) and isr[1] == serial


def _ess_cert_ids(o: str, certs: bytes) -> Union[str, List[tuple]]:
    """the ESSCertID(v2)s of one attribute, closed: [(hash algorithm, certHash, (issuer Name TLV, serial) or None)], or why
    not (spec §5 step 8 (a), 0.13.0: RFC 2634 §5.4, RFC 5035 §3; ported from cryptovalid-opencore SPEC §11 step 7 v0.11)"""
    ids = _items(certs)
    if not ids:
        return f"ESS attribute {o}: no ESSCertID"
    out: List[tuple] = []
    for n, (t, v) in enumerate(ids, 1):
        if t != 0x30:
            return f"ESS attribute {o}: ESSCertID {n} is not a SEQUENCE"
        cid = _items(v)
        alg: Optional[str] = "sha1"
        if o == _OID_SIGNING_CERTIFICATE_V2:
            alg = "sha256"
            if cid and cid[0][0] == 0x30:
                ai = _items(cid[0][1])
                alg = _ESS_HASHES.get(_oid_of(ai[0][1])) if ai and ai[0][0] == 0x06 else None
                if alg is None or not (len(ai) == 1 or (len(ai) == 2 and ai[1] == (0x05, b""))):
                    return f"ESSCertIDv2 {n}: hash algorithm not known"
                cid = cid[1:]
        if not cid or cid[0][0] != 0x04 or len(cid) > 2 or (len(cid) == 2 and cid[1][0] != 0x30):
            return f"ESSCertID {n}: not {{certHash, issuerSerial?}}"
        if len(cid[0][1]) != hashlib.new(alg).digest_size:
            return f"ESSCertID {n}: certHash is not {alg}-long"
        isr = None
        if len(cid) == 2:
            iss = _items(cid[1][1])
            names = _items(_one(_tlv(0x30, iss[0][1]), 0x30)) if iss and iss[0][0] == 0x30 else None
            if not (len(iss) == 2 and iss[1][0] == 0x02 and names is not None and len(names) == 1
                    and names[0][0] == 0xA4):
                return f"ESSCertID {n}: issuerSerial is not {{one directoryName, serialNumber}}"
            isr = (names[0][1], int.from_bytes(iss[1][1], "big", signed=True))
        if any(alg == a and cid[0][1] == h for a, h, _ in out):   # closed: a certificate listed twice is refused
            return f"ESSCertID {n}: the same certificate hash as an earlier ESSCertID"
        out.append((alg, cid[0][1], isr))
    return out


def _ess_lists_more_than_one(token_der: bytes) -> bool:
    """spec §5 step 8 (0.13.0): a signingCertificate(V2) attribute of the SignerInfo lists more than one ESSCertID.
    Anything not read here answers False (the route of `ts -verify`)."""
    try:
        sis = _signer_infos(token_der)
        si = _items(sis[0][1])
        for t, av in _items(si[3][1]) if si[3][0] == 0xA0 else []:
            a = _items(av) if t == 0x30 else []
            if len(a) != 2 or a[0][0] != 0x06 or a[1][0] != 0x31:
                continue
            if _oid_of(a[0][1]) not in (_OID_SIGNING_CERTIFICATE, _OID_SIGNING_CERTIFICATE_V2):
                continue
            for t2, v in _items(a[1][1]):
                sc = _items(v) if t2 == 0x30 else []
                if sc and sc[0][0] == 0x30 and len(_items(sc[0][1])) > 1:
                    return True
        return False
    except (TokenRefused, IndexError, ValueError):
        return False


_SIGNER_NOT_FOUND = b"signer certificate not found"   # OpenSSL CMS_R_SIGNER_CERTIFICATE_NOT_FOUND (CMS_verify)


def _signer_certificate_absent(token_der: bytes, pins_pem: bytes) -> bool:
    """spec §5 step 7 (0.13.0): True only when every certificate of the token and every pinned one was read and none is
    the one the SignerInfo's sid names (issuerAndSerialNumber: issuer as X509_NAME_cmp, serial as an integer;
    subjectKeyIdentifier: the certificate's subjectKeyIdentifier extension). Anything not read answers False: the
    absence is never presumed. Ported from cryptovalid-opencore SPEC §11 step 6 (v0.11)."""
    try:
        sis = _signer_infos(token_der)
        if len(sis) != 1 or sis[0][0] != 0x30:
            return False
        sid = _items(sis[0][1])[1]
        certs: List[bytes] = []
        for tag, val in _signed_data(token_der)[3:-1]:
            if tag == 0xA0:
                for t, v in _items(val):
                    if t != 0x30:                      # another CertificateChoices: not read here
                        return False
                    certs.append(_tlv(t, v))
        pinned = _pem_ders(pins_pem)
        if pins_pem.count(b"-----BEGIN") != len(pinned) or not all(pinned):
            return False
        certs += pinned
        if sid[0] == 0x30:
            ias = _items(sid[1])
            if len(ias) != 2 or ias[0][0] != 0x30 or ias[1][0] != 0x02:
                return False
            want_issuer = _name_canon(_tlv(0x30, ias[0][1]))   # raises on a Name not read: absence not presumed
            want_serial = int.from_bytes(ias[1][1], "big", signed=True)
        elif sid[0] == 0x80:
            want_ski = sid[1]
        else:
            return False
        for der in certs:
            cert = _items(_one(der, 0x30))
            tbs = _items(cert[0][1])
            k = 1 if tbs[0][0] == 0xA0 else 0
            if tbs[k][0] != 0x02 or tbs[k + 2][0] != 0x30 or tbs[k + 5][0] != 0x30:
                return False
            if sid[0] == 0x30:
                if _name_canon(_tlv(0x30, tbs[k + 2][1])) == want_issuer and \
                        int.from_bytes(tbs[k][1], "big", signed=True) == want_serial:
                    return False
                continue
            for t, v in tbs[k + 6:]:
                if t != 0xA3:
                    continue
                for et, ev in _items(_one(v, 0x30)):
                    ext = _items(ev) if et == 0x30 else []
                    if not ext or ext[0][0] != 0x06:
                        return False
                    if _oid_of(ext[0][1]) == "2.5.29.14" and ext[-1][0] == 0x04 and _one(ext[-1][1], 0x04) == want_ski:
                        return False
        return True
    except (TokenRefused, IndexError, ValueError):
        return False


def _key_id_anchor(token_der: bytes, signer_der: bytes, pins_pem: bytes, at: int, tmp: str,
                   timeout: float = 30.0) -> Optional[str]:
    """spec §5 step 8 for a signer named by subjectKeyIdentifier, and (0.13.0) for any signer whose signing-certificate
    attribute lists more than one ESSCertID: None when the token is established under the pinned certificates, else why
    not. One SignerInfo with signed attributes; (a) ESS signing-certificate attribute(s): the first ESSCertID is the
    signer certificate, the ones after it limit the token's certificates the path may use, (b) the
    `tsa` field, (c) openssl verify with the timestampsign purpose, the chain to a pinned certificate and the validity
    at genTime, no system store."""
    try:
        sis = _signer_infos(token_der)
        if len(sis) != 1 or sis[0][0] != 0x30:
            return f"{len(sis)} SignerInfos (exactly one is evaluated here)"
        si = _items(sis[0][1])
        if len(si) < 4 or si[3][0] != 0xA0:
            return "the SignerInfo has no signed attributes"
        sd = _signed_data(token_der)
        eci = _items(sd[2][1])
        tst = _items(_one(_one(eci[1][1], 0x04), 0x30))
        cert = _items(_one(signer_der, 0x30))
        tbs = _items(cert[0][1])
        k = 1 if tbs[0][0] == 0xA0 else 0
        subject = _tlv(0x30, tbs[k + 4][1])
        san: List[bytes] = []
        for tag, v in tbs[k + 6:]:
            if tag == 0xA3:
                for _t, ev in _items(_one(v, 0x30)):
                    e = _items(ev)
                    if _oid_of(e[0][1]) == _OID_SUBJECT_ALT_NAME:
                        san = [_tlv(gt, gv) for gt, gv in _items(_one(e[-1][1], 0x30))]
        # (a) ESS
        attrs: Dict[str, List[bytes]] = {}
        for t, av in _items(si[3][1]):   # Attribute ::= SEQUENCE { attrType OID, attrValues SET }, nothing else
            a = _items(av)
            if t != 0x30 or len(a) != 2 or a[0][0] != 0x06 or a[1][0] != 0x31:
                return "a signed attribute is not {attrType, attrValues SET}"
            attrs.setdefault(_oid_of(a[0][1]), []).append(a[1][1])
        found = [o for o in (_OID_SIGNING_CERTIFICATE, _OID_SIGNING_CERTIFICATE_V2) if o in attrs]
        if not found:
            return "no signingCertificate or signingCertificateV2 attribute (ESS)"
        token_certs = _token_certificates(token_der)
        pool = token_certs + _pem_ders(pins_pem)
        allowed: Optional[set] = None   # None: no attribute limits the path (one ESSCertID each)
        for o in found:
            vals = attrs[o]
            if len(vals) != 1 or len(_items(vals[0])) != 1:
                return f"ESS attribute {o}: not exactly one value"
            sc = _items(_one(vals[0], 0x30))   # SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF, policies OPTIONAL }
            if not 1 <= len(sc) <= 2 or sc[0][0] != 0x30 or (len(sc) == 2 and not _policies_shape(sc[1])):
                return f"ESS attribute {o}: not {{certs, policies?}}"
            ids = _ess_cert_ids(o, sc[0][1])
            if isinstance(ids, str):
                return ids
            alg, h, isr = ids[0]            # RFC 2634 §5.4, RFC 5035 §3: the first is the signer certificate
            if h != hashlib.new(alg, signer_der).digest():
                return "ESS certHash is not the hash of the signer certificate"
            if isr is not None and not _ess_names(isr, signer_der):
                return "ESS issuerSerial does not name the signer certificate's issuer and serial number"
            if len(ids) > 1:                # the ones after it "limit the set of certificates" (spec §5 step 8, 0.13.0)
                ok = {signer_der}
                for n, (alg, h, isr) in enumerate(ids[1:], 2):
                    for c in pool:
                        if hashlib.new(alg, c).digest() == h:
                            if isr is not None and not _ess_names(isr, c):
                                return f"ESSCertID {n}: issuerSerial does not name the certificate whose hash it carries"
                            ok.add(c)
                allowed = ok if allowed is None else allowed & ok
        # (b) the tsa field
        tsa = [v for tag, v in tst[5:] if tag == 0xA0]
        if tsa:   # ts_check_signer_name: the subject (a directoryName), then each name of the subjectAltName
            gn = _items(tsa[0])
            if len(gn) != 1 or not (_general_names_equal(gn[0], (0xA4, subject))
                                    or any(_general_names_equal(gn[0], _items(n)[0]) for n in san)):
                return "the TSTInfo tsa field names neither the signer's subject nor one of its subjectAltName"
    except (TokenRefused, IndexError, ValueError) as e:
        return f"signer certificate or attributes not read: {e}"[:160]
    # (c) chain, purpose, validity at genTime: the OpenSSL chain building of ts -verify, no system store
    sp, cp, up = (os.path.join(tmp, n) for n in ("ski_signer.pem", "ski_pinned.pem", "ski_untrusted.pem"))
    for path, data in ((sp, _pem(signer_der)), (cp, pins_pem),
                       (up, pins_pem + b"".join(_pem(c) for c in token_certs if allowed is None or c in allowed))):
        with open(path, "wb") as f:
            f.write(data)
    p = _openssl(["verify", "-purpose", "timestampsign", "-partial_chain", "-attime", str(at), "-CAfile", cp,
                  "-no-CApath", "-no-CAstore", "-untrusted", up, sp], timeout)
    err = (p.stderr or b"") + (p.stdout or b"")
    if p.returncode != 0 and b"nknown option" in err:
        raise TimeAnchorNotRun("this openssl does not know an option of `verify` (OpenSSL 3.0 or later is needed): "
                               + err.decode("utf-8", "replace").strip()[-160:])
    if p.returncode != 0:
        return (err.decode("utf-8", "replace").strip() or "openssl verify refused the signer certificate")[-200:]
    return None


def make_timestamp_trust_fn(lte: LongTermEvidence, tsa_certs: Sequence[Union[str, bytes]],
                            timeout: float = 30.0) -> Callable[[Dict[str, Any]], bool]:
    """spec/TIME_ANCHOR.md §5: the function `lte.verify(..., timestamp_trust_fn=...)` calls on each record of `lte`.
    `tsa_certs`: the TSA certificate(s) the verifier pins (the TSA's certificate or a CA above it)."""
    pins = _pins_pem(tsa_certs)
    log: List[Dict[str, Any]] = []

    def no(reason: str, detail: Optional[str] = None) -> bool:
        log.append({"ok": False, "reason": reason, "detail": detail})
        return False

    def fn(rec: Dict[str, Any]) -> bool:
        i = next((k for k, r in enumerate(lte.records) if r is rec), None)
        if i is None:
            return no("record_not_in_chain")
        if rec.get("ts_source") != "rfc3161":
            return no("ts_source_not_rfc3161", str(rec.get("ts_source")))
        if "anchor" not in rec:
            return no("digest_only_binding", "sealed before spec/TIME_ANCHOR.md: the token stamps the evidence digest only")
        if rec.get("anchor") != ANCHOR:
            return no("anchor_unknown", str(rec.get("anchor"))[:80])
        extra = [k for k in rec if k not in _RECORD_FIELDS]
        if extra:   # NEMESIS 15/11/2026: a signed field the token does not stamp was accepted with the record "verified"
            return no("unknown_field", repr(extra)[:200])
        tok = rec.get("token_b64")
        if not isinstance(tok, str) or not tok:
            return no("token_missing")
        try:
            raw = base64.b64decode(tok.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            return no("token_not_base64")
        try:
            alg_oid, hashed, gen = rfc3161_tstinfo(raw)
            der = timestamp_token_der(raw)
        except (TokenRefused, IndexError, ValueError) as e:
            return no("token_malformed", str(e)[:200])
        name = _HASH_NAMES.get(alg_oid)
        if name is None or hashed != lte.anchor_imprint_bytes(i, rec, name):
            return no("imprint_mismatch", f"{alg_oid}: {hashed.hex()[:64]}")
        t = rec.get("t")
        try:   # §3: the string longterm.py writes, repr(float(...)); float() alone took " 1.0\n", "+1.0", "1_0.0", "10"
            same_time = isinstance(t, str) and t == repr(gen_time_seconds(gen))
        except ValueError:
            same_time = False
        if not same_time:
            return no("t_not_gen_time", f"t {rec.get('t')!r}, genTime {gen}")
        d = tempfile.mkdtemp(prefix="cra-tsa-")
        try:
            tp, cp = os.path.join(d, "token.der"), os.path.join(d, "pins.pem")
            with open(tp, "wb") as f:
                f.write(der)
            with open(cp, "wb") as f:
                f.write(pins)
            sp = os.path.join(d, "signer.pem")
            p = _openssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", tp, "-binary", "-certfile", cp,
                          "-signer", sp, "-out", os.devnull], timeout)
            if p.returncode != 0:
                err = p.stderr or b""
                # §5 step 7 (0.13.0): not evaluated when openssl stopped at the signer lookup AND the sid names no
                # certificate read here (a token openssl cannot parse stays signature_invalid: ETSI EN 319 102-1 §5.3.4)
                if _SIGNER_NOT_FOUND in err and _signer_certificate_absent(der, pins):
                    log.append({"ok": None, "reason": "signer_certificate_absent",
                                "detail": "signature not evaluated: the certificate the SignerInfo names is neither in the "
                                          "token nor pinned (pin the TSA certificate; ETSI EN 319 102-1 §5.2.3.3)"})
                    return False
                return no("signature_invalid", err.decode("utf-8", "replace").strip()[-200:])
            at = int(gen_time_seconds(gen))
            # §5 step 8: subjectKeyIdentifier, which openssl ts cannot read; more than one ESSCertID (0.13.0), where
            # openssl ts asks every ESSCertID to be in the chain it built, which RFC 2634 §5.4 / RFC 5035 do not ask
            if _signer_named_by_key_id(der) or _ess_lists_more_than_one(der):
                signer = []
                if os.path.isfile(sp):
                    with open(sp, "rb") as f:
                        signer = [_pem_block_der(bl) for bl in f.read().split(b"-----BEGIN CERTIFICATE-----")[1:]]
                if len(signer) != 1 or not _is_certificate_der(signer[0]):
                    return no("not_issued_by_pinned_tsa", f"signer certificate not read ({len(signer)} written by openssl)")
                why = _key_id_anchor(der, signer[0], pins, at, d, timeout)
                if why is not None:
                    return no("not_issued_by_pinned_tsa", why)
            else:
                p = _openssl(["ts", "-verify", "-token_in", "-in", tp, "-digest", hashed.hex(), "-CAfile", cp,
                              "-untrusted", cp, "-partial_chain", "-attime", str(at)], timeout)
                if p.returncode != 0 or b"Verification: OK" not in (p.stdout or b"").splitlines():
                    return no("not_issued_by_pinned_tsa", (p.stderr or b"").decode("utf-8", "replace").strip()[-200:])
        finally:
            shutil.rmtree(d, ignore_errors=True)
        if rec.get("token_sha3") != hashlib.sha3_256(tok.encode("ascii")).hexdigest():   # NEMESIS 15/11/2026: the
            return no("token_sha3_mismatch", str(rec.get("token_sha3"))[:80])          # derived field must agree
        log.append({"ok": True, "reason": None, "detail": gen})
        return True

    setattr(fn, "log", log)   # the closed reason of every answer, in order
    return fn

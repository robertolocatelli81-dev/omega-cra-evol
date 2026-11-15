# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shape of a time token given to `cra seal` (no signature, no certificate, no time is VERIFIED here).

`rfc3161_tstinfo` reads an RFC 3161 TimeStampResp whose status is granted (0) or granted with mods (1), or the
TimeStampToken itself (a CMS ContentInfo, signedData), whose encapsulated content type is id-ct-TSTInfo
(1.2.840.113549.1.9.16.1.4): its messageImprint and its genTime. What a seal's token must stamp is in
spec/TIME_ANCHOR.md (longterm.seal checks it). `check_token` keeps the shape of 0.9.0-0.11.1: for
`ts_source="rfc3161"`, a SHA3-256 (2.16.840.1.101.3.4.2.8) imprint over the 32 bytes of the sealed digest; `cra seal` no
longer uses that branch. `ts_source="ots"`: the token must start with the OpenTimestamps file header (it is not parsed
further).

What this does NOT do: verify the CMS signature, the TSA certificate, its EKU or its chain, nor trust the genTime.
That is omega_cra_evol.time_anchor.make_timestamp_trust_fn, against the TSA certificates a verifier pins."""
from __future__ import annotations

# The names other code may import from this module (provisional tier of API.md: typed, may change in a minor
# release with a changelog note). Everything else here is private. tests/test_api_surface.py keeps the list.
__all__ = [
    "OID_SHA256", "OID_SHA3_256", "OID_SIGNED_DATA", "OID_TSTINFO", "OTS_MAGIC", "TS_SOURCES", "TokenRefused",
    "check_token", "gen_time_seconds", "rfc3161_imprint", "rfc3161_tstinfo", "timestamp_token_der",
]

import base64
import binascii
import re
from typing import List, Tuple

TS_SOURCES = ("asserted", "rfc3161", "ots")
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA3_256 = "2.16.840.1.101.3.4.2.8"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


class TokenRefused(ValueError):
    pass


def _tlv(b: bytes, i: int) -> Tuple[int, int, int]:
    """(tag, start of value, end of value) of the DER element at i: one-byte tags, definite minimal lengths"""
    if i + 2 > len(b):
        raise TokenRefused("truncated DER")
    tag, n = b[i], b[i + 1]
    if tag & 0x1F == 0x1F:
        raise TokenRefused("multi-byte DER tag")
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(b) or b[i] == 0:
            raise TokenRefused("DER length not definite and minimal")
        n = int.from_bytes(b[i:i + k], "big")
        if n < 0x80:
            raise TokenRefused("DER length not minimal")
        i += k
    if i + n > len(b):
        raise TokenRefused("truncated DER")
    return tag, i, i + n


def _children(b: bytes, s: int, e: int) -> List[Tuple[int, int, int]]:
    out = []
    while s < e:
        t = _tlv(b, s)
        if t[2] > e:
            raise TokenRefused("DER element beyond its parent")
        out.append(t)
        s = t[2]
    return out


def _oid(b: bytes, t: Tuple[int, int, int]) -> str:
    tag, s, e = t
    if tag != 0x06 or s == e:
        raise TokenRefused("OBJECT IDENTIFIER expected")
    arcs, v = [], 0
    for x in b[s:e]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            arcs.append(v)
            v = 0
    if b[e - 1] & 0x80:
        raise TokenRefused("OBJECT IDENTIFIER truncated")
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first] + arcs[1:])


def _int(b: bytes, t: Tuple[int, int, int]) -> int:
    if t[0] != 0x02 or t[1] == t[2]:
        raise TokenRefused("INTEGER expected")
    return int.from_bytes(b[t[1]:t[2]], "big", signed=True)


def _whole(b: bytes) -> Tuple[int, int, int]:
    t = _tlv(b, 0)
    if t[2] != len(b):
        raise TokenRefused("bytes after the DER element")
    return t


def rfc3161_imprint(der: bytes) -> Tuple[str, bytes]:
    """(hash algorithm OID, hashedMessage) of the TSTInfo inside a TimeStampResp or a TimeStampToken"""
    alg, h, _ = rfc3161_tstinfo(der)
    return alg, h


def _token_span(der: bytes) -> Tuple[int, int, List[Tuple[int, int, int]]]:
    """(start, end) of the TimeStampToken inside `der` (a TimeStampResp or the token itself) and the token's two
    children (contentType, [0] content)."""
    tag, s, e = _whole(der)
    if tag != 0x30:
        raise TokenRefused("not a DER SEQUENCE")
    kids = _children(der, s, e)
    start, end = 0, len(der)
    if kids and kids[0][0] == 0x30:              # TimeStampResp: status, then the token
        st = _children(der, kids[0][1], kids[0][2])
        if not st or _int(der, st[0]) not in (0, 1):
            raise TokenRefused("TimeStampResp status is not granted (0) or grantedWithMods (1)")
        if len(kids) != 2:
            raise TokenRefused("TimeStampResp without a timeStampToken")
        if kids[1][0] == 0x30:
            start, end = kids[0][2], kids[1][2]       # the token's TLV starts where the status ends
            kids = _children(der, kids[1][1], kids[1][2])
        else:
            kids = []
    if len(kids) != 2 or _oid(der, kids[0]) != OID_SIGNED_DATA or kids[1][0] != 0xA0:
        raise TokenRefused("not a CMS ContentInfo with signedData")
    return start, end, kids


def timestamp_token_der(der: bytes) -> bytes:
    """The TimeStampToken (CMS ContentInfo) itself, from a TimeStampResp or from the token"""
    start, end, _ = _token_span(der)
    return der[start:end]


def rfc3161_tstinfo(der: bytes) -> Tuple[str, bytes, str]:
    """(hash algorithm OID, hashedMessage, genTime as written) of the TSTInfo inside a TimeStampResp or a
    TimeStampToken. genTime must be a GeneralizedTime of RFC 3161 §2.4.2: YYYYMMDDhhmmss[.f+]Z, no trailing zero in the
    fraction (spec/TIME_ANCHOR.md §3)."""
    _, _, kids = _token_span(der)
    sd = _children(der, kids[1][1], kids[1][2])
    if len(sd) != 1 or sd[0][0] != 0x30:
        raise TokenRefused("signedData is not a SEQUENCE")
    sd = _children(der, sd[0][1], sd[0][2])
    if len(sd) < 4 or sd[2][0] != 0x30:
        raise TokenRefused("SignedData without encapContentInfo")
    eci = _children(der, sd[2][1], sd[2][2])
    if len(eci) != 2 or _oid(der, eci[0]) != OID_TSTINFO or eci[1][0] != 0xA0:
        raise TokenRefused("the encapsulated content is not id-ct-TSTInfo")
    oc = _children(der, eci[1][1], eci[1][2])
    if len(oc) != 1 or oc[0][0] != 0x04:
        raise TokenRefused("eContent is not an OCTET STRING")
    tst = der[oc[0][1]:oc[0][2]]
    t = _whole(tst)
    if t[0] != 0x30:
        raise TokenRefused("TSTInfo is not a SEQUENCE")
    f = _children(tst, t[1], t[2])
    if len(f) < 5 or _int(tst, f[0]) != 1:
        raise TokenRefused("TSTInfo version is not 1")
    _oid(tst, f[1])                                   # policy
    if f[2][0] != 0x30:
        raise TokenRefused("messageImprint is not a SEQUENCE")
    mi = _children(tst, f[2][1], f[2][2])
    if len(mi) != 2 or mi[0][0] != 0x30 or mi[1][0] != 0x04:
        raise TokenRefused("messageImprint malformed")
    alg = _children(tst, mi[0][1], mi[0][2])
    if not alg:
        raise TokenRefused("messageImprint hashAlgorithm malformed")
    _int(tst, f[3])                                   # serialNumber
    if f[4][0] != 0x18:
        raise TokenRefused("TSTInfo genTime is not a GeneralizedTime")
    try:
        gen = tst[f[4][1]:f[4][2]].decode("ascii")
    except UnicodeDecodeError:
        raise TokenRefused("TSTInfo genTime is not ASCII") from None
    if not _GEN_TIME.fullmatch(gen) or (("." in gen) and gen[-2] == "0"):
        raise TokenRefused(f"TSTInfo genTime {gen[:40]!r} is not YYYYMMDDhhmmss[.f]Z (RFC 3161 §2.4.2)")
    gen_time_seconds(gen)                             # a real calendar time
    return _oid(tst, alg[0]), tst[mi[1][1]:mi[1][2]], gen


_GEN_TIME = re.compile(r"[0-9]{14}(\.[0-9]+)?Z")


def gen_time_seconds(gen: str) -> float:
    """spec/TIME_ANCHOR.md §3: genTime (YYYYMMDDhhmmss[.f]Z, UTC) as seconds since 1970-01-01T00:00:00Z: the calendar
    seconds, then the fraction digits as written, read as one decimal string by float()."""
    import calendar
    from datetime import datetime
    try:
        secs = calendar.timegm(datetime.strptime(gen[:14], "%Y%m%d%H%M%S").timetuple())
    except ValueError:
        raise TokenRefused(f"TSTInfo genTime {gen[:40]!r} is not a calendar time") from None
    frac = gen[15:-1] if gen[14:15] == "." else ""
    return float(f"{secs}.{frac}" if frac else f"{secs}")


def check_token(ts_source: str, token_b64: str, evidence_digest: str) -> None:
    """refuse (TokenRefused, with the reason) a token that is not of the shape its ts_source names"""
    if ts_source not in TS_SOURCES:
        raise TokenRefused(f"ts_source {ts_source!r}: one of {list(TS_SOURCES)}")
    if ts_source == "asserted":
        if token_b64 is not None:
            raise TokenRefused("ts_source 'asserted' takes no token (a token names its source: rfc3161 or ots)")
        return
    if not isinstance(token_b64, str) or not token_b64:
        raise TokenRefused(f"ts_source {ts_source!r} needs the timestamp token (token_b64)")
    try:
        raw = base64.b64decode(token_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise TokenRefused("token_b64 is not standard base64") from None
    if ts_source == "ots":
        if not raw.startswith(OTS_MAGIC):
            raise TokenRefused("the token does not start with the OpenTimestamps file header")
        return
    try:
        alg, h = rfc3161_imprint(raw)
    except TokenRefused as e:
        raise TokenRefused(f"the token is not an RFC 3161 TimeStampResp / TimeStampToken: {e}") from None
    except (IndexError, ValueError) as e:
        raise TokenRefused(f"the token is not an RFC 3161 TimeStampResp / TimeStampToken: {type(e).__name__}") from None
    if alg != OID_SHA3_256 or h != bytes.fromhex(evidence_digest):
        raise TokenRefused(f"the token's messageImprint ({alg}, {h.hex()[:64]}) is not SHA3-256 over the sealed digest "
                           f"{evidence_digest}")

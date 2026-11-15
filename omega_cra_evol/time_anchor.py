# SPDX-License-Identifier: AGPL-3.0-or-later
"""A `timestamp_trust_fn` for LongTermEvidence.verify that can refuse (spec/TIME_ANCHOR.md §5, cra-lta-time-anchor/1).

Until this module the package shipped none: `verify` without one says `temporal_trust: ASSUMED`, and the package's own
tests injected `lambda r: True`, under which a record whose "token" is the string `not base64!` was verified. This
function checks, for each record, that its RFC 3161 token stamps that record (the evidence digest, every previous record
and the record's own fields), that the record's time is the token's genTime, that the token's signature verifies, and
that the TSA is one the verifier pins (openssl `cms -verify` and `ts -verify`, as cryptovalid-opencore's SPEC §11 does
for its tokens). Proposed by Athena's review of 15/11/2026 (its prototype p5_timestamp_trust.py), rewritten here.

It returns a bool (the interface of longterm.verify); the closed reason of each answer is appended to `fn.log`. An
openssl that is absent or cannot run is not a refusal: TimeAnchorNotRun is raised and no verdict is given."""
from __future__ import annotations

# The names other code may import from this module (provisional tier of API.md). tests/test_api_surface keeps the list.
__all__ = ["REASONS", "TimeAnchorNotRun", "make_timestamp_trust_fn"]

import base64
import binascii
import os
import shutil
import subprocess  # nosec B404 - openssl only, fixed arguments, no shell
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .longterm import ANCHOR, LongTermEvidence
from .rfc3161_token import (OID_SHA256, OID_SHA3_256, TokenRefused, gen_time_seconds, rfc3161_tstinfo,
                            timestamp_token_der)

REASONS = ("record_not_in_chain", "ts_source_not_rfc3161", "digest_only_binding", "anchor_unknown", "token_missing",
           "token_not_base64", "token_malformed", "imprint_mismatch", "t_not_gen_time", "signature_invalid",
           "not_issued_by_pinned_tsa")
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
            with open(c, "rb") as f:
                c = f.read()
        if not isinstance(c, (bytes, bytearray)) or not c:
            raise ValueError("tsa_certs: an entry is neither a path nor certificate bytes")
        c = bytes(c)
        if b"-----BEGIN CERTIFICATE-----" in c:
            out += c if c.endswith(b"\n") else c + b"\n"
        elif c[:1] == b"\x30":
            b64 = base64.b64encode(c)
            out += b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + \
                b"\n-----END CERTIFICATE-----\n"
        else:
            raise ValueError("tsa_certs: an entry is not a PEM or DER certificate")
    return out


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
        try:
            same_time = isinstance(t, str) and float(t) == gen_time_seconds(gen)
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
            p = _openssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", tp, "-binary", "-certfile", cp,
                          "-out", os.devnull], timeout)
            if p.returncode != 0:
                return no("signature_invalid", (p.stderr or b"").decode("utf-8", "replace").strip()[-200:])
            at = int(gen_time_seconds(gen))
            p = _openssl(["ts", "-verify", "-token_in", "-in", tp, "-digest", hashed.hex(), "-CAfile", cp, "-untrusted", cp,
                          "-partial_chain", "-attime", str(at)], timeout)
            if p.returncode != 0 or b"Verification: OK" not in (p.stdout or b"").splitlines():
                return no("not_issued_by_pinned_tsa", (p.stderr or b"").decode("utf-8", "replace").strip()[-200:])
        finally:
            shutil.rmtree(d, ignore_errors=True)
        log.append({"ok": True, "reason": None, "detail": gen})
        return True

    setattr(fn, "log", log)   # the closed reason of every answer, in order
    return fn

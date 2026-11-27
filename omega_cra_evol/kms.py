# SPDX-License-Identifier: AGPL-3.0-or-later
"""AWS KMS Ed25519 signer (key spec ECC_NIST_EDWARDS25519, SigningAlgorithm ED25519_SHA_512, MessageType RAW):
the private key never leaves the HSM; this module is HTTP + SigV4 with the standard library only (no SDK).
It plugs into `sign_pack(pack, key=(signer, public_key_hex), …)` because it exposes `.sign(bytes) -> bytes`.

Honest scope: the SigV4 derivation is validated against the official AWS test vector (tests); the end-to-end
round-trip needs a real account and is exercised on the author's key when a release is signed (recorded in the
release notes with the public key). Credentials from arguments or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
AWS_SESSION_TOKEN; a custom endpoint must be https or loopback (a session token must never travel in clear) and
without user information; a failed request is reported by its kind, errno and HTTP status, never its text."""
from __future__ import annotations

# The names other code may import from this module (provisional tier of API.md: typed, may change in a minor
# release with a changelog note). Everything else here is private. tests/test_api_surface.py keeps the list.
__all__ = [
    "KMSSigner", "derive_signing_key", "load_creds_file", "sigv4_headers",
]

import base64
import datetime
import hashlib
import hmac
import http.client
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

# the variables this module reads: secrets, or a URL that can hold one. No child process of the package receives them
# (time_anchor runs openssl without them, 0.13.2)
_SECRET_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_KMS_ENDPOINT")


def derive_signing_key(secret_key: str, datestamp: str, region: str, service: str) -> bytes:
    """AWS SigV4 signing-key derivation (HMAC chain)."""
    def _s(k: bytes, m: str) -> bytes:
        return hmac.new(k, m.encode(), hashlib.sha256).digest()
    return _s(_s(_s(_s(("AWS4" + secret_key).encode(), datestamp), region), service), "aws4_request")


def sigv4_headers(host: str, region: str, service: str, target: str, body: bytes, access_key: str, secret_key: str,
                  session_token: Optional[str], amzdate: str, datestamp: str) -> Dict[str, str]:
    ct = "application/x-amz-json-1.1"
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers = f"content-type:{ct}\nhost:{host}\nx-amz-date:{amzdate}\nx-amz-target:{target}\n"
    signed_headers = "content-type;host;x-amz-date;x-amz-target"
    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    signature = hmac.new(derive_signing_key(secret_key, datestamp, region, service), sts.encode(), hashlib.sha256).hexdigest()
    headers = {"Content-Type": ct, "X-Amz-Date": amzdate, "X-Amz-Target": target,
               "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"}
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


class KMSSigner:
    """`.sign(msg)` (Ed25519 raw, 64 bytes) and `.public_key_hex` (32 bytes raw, read from KMS at construction)."""
    alg = "Ed25519"

    def __init__(self, key_id: str, region: str, access_key: Optional[str] = None, secret_key: Optional[str] = None,
                 session_token: Optional[str] = None, endpoint: Optional[str] = None, timeout: int = 15):
        self.key_id, self.region, self.timeout = key_id, region, timeout
        self._ak = access_key or os.environ.get("AWS_ACCESS_KEY_ID", "")
        self._sk = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        self._st = session_token or os.environ.get("AWS_SESSION_TOKEN")
        if not (self._ak and self._sk):
            raise RuntimeError("AWS KMS: credentials absent (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)")
        self._host = f"kms.{region}.amazonaws.com"
        ep = endpoint or os.environ.get("AWS_KMS_ENDPOINT")
        if ep:
            u = urllib.parse.urlsplit(ep)
            if "@" in u.netloc:   # user information is refused before the network, and the URL is not repeated (0.13.2)
                raise ValueError("AWS KMS custom endpoint must not carry user information (user:password@)")
            loop = (u.hostname or "").lower() in ("127.0.0.1", "localhost", "::1")
            # NEMESIS 15/11/2026: any scheme towards a loopback host passed (file://localhost/..., ftp://localhost/...),
            # as in cryptovalid-opencore before its 0.25.0 rule: https, or plain http to a loopback host, and nothing else
            if not (u.scheme == "https" and u.hostname) and not (u.scheme == "http" and loop):
                raise ValueError("AWS KMS custom endpoint must be https (or http to a loopback host)")
        self._endpoint = ep or f"https://{self._host}"
        self.public_key_hex = self._read_pubkey()

    def _call(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload).encode()
        now = datetime.datetime.now(datetime.timezone.utc)
        headers = sigv4_headers(self._host, self.region, "kms", target, body, self._ak, self._sk, self._st,
                                now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"))
        req = urllib.request.Request(self._endpoint.rstrip("/") + "/", data=body, headers=headers, method="POST")
        # a loopback endpoint (a local KMS emulator) is reached directly: an environment proxy cannot reach this host's
        # loopback, and would receive the signed request (15/11/2026); AWS itself goes through the proxy, if any
        loopback = (urllib.parse.urlsplit(self._endpoint).hostname or "").lower() in ("127.0.0.1", "localhost", "::1")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if loopback else urllib.request.build_opener()
        try:
            with opener.open(req, timeout=self.timeout) as r:  # nosec B310 — fixed AWS endpoint, or loopback
                return json.load(r)
        except (OSError, http.client.HTTPException) as e:   # its kind, its errno and HTTP status: never its text (0.13.2)
            n = e.errno if isinstance(e, OSError) and e.errno else getattr(getattr(e, "reason", None), "errno", None)
            code = getattr(e, "code", None)
            what = f"AWS KMS request failed: {type(e).__name__}" + (f" HTTP {code}" if isinstance(code, int) else "")
            raise (OSError(n, what) if isinstance(n, int) else OSError(what)) from None

    def _read_pubkey(self) -> str:
        der = base64.b64decode(self._call("TrentService.GetPublicKey", {"KeyId": self.key_id})["PublicKey"])
        # SubjectPublicKeyInfo for Ed25519 (RFC 8410): 12-byte prefix 302a300506032b6570032100 + 32 raw bytes
        if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
            raise RuntimeError("the AWS KMS key is not Ed25519 (use key spec ECC_NIST_EDWARDS25519)")
        return der[12:].hex()

    def sign(self, data: bytes) -> bytes:
        r = self._call("TrentService.Sign", {"KeyId": self.key_id, "Message": base64.b64encode(data).decode(),
                                              "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})
        sig = base64.b64decode(r["Signature"])
        if len(sig) != 64:
            raise RuntimeError("KMS returned a signature that is not 64 bytes")
        return sig

    def as_key(self) -> Tuple["KMSSigner", str]:
        """The (signer, public_key_hex) pair that sign_pack / seal_longterm accept."""
        return self, self.public_key_hex


def load_creds_file(path: str) -> Dict[str, str]:
    """KEY=VALUE lines (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, optional AWS_SESSION_TOKEN); never logged."""
    out: Dict[str, str] = {}
    from .ledger import _read_secret_file   # a regular file within the bound (a FIFO or a device is refused unread); never its path
    for line in _read_secret_file(path).decode("utf-8").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.strip().split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out

"""AWS KMS signing path, run end to end against a local KMS emulator on loopback (15/11/2026).

Before, the tests checked only the SigV4 header: `_call`, `_read_pubkey` and `sign` never ran (copertura di kms.py 65 %).
Here a loopback server answers GetPublicKey and Sign as AWS KMS does (JSON over POST, SPKI DER of an Ed25519 key,
a raw 64-byte signature); the signature is checked with the public key the signer read. An environment proxy that
cannot be reached (port 9) is set while the signer runs: a loopback endpoint is reached directly."""
import base64
import http.server
import json
import os
import subprocess
import sys
import threading
import unittest
from unittest import mock

from omega_cra_evol.kms import KMSSigner

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    HAVE = True
except ImportError:   # pragma: no cover - the [sign] extra is absent
    HAVE = False

SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class FakeKMS:
    """GetPublicKey / Sign of one Ed25519 key; `mode` makes it answer wrongly on purpose."""

    def __init__(self, mode="ok"):
        self.key = Ed25519PrivateKey.generate()
        self.mode, self.calls = mode, []
        owner = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                target = self.headers.get("X-Amz-Target")
                owner.calls.append((target, self.headers.get("Authorization", "")))
                if target == "TrentService.GetPublicKey":
                    raw = owner.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    der = (bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04" + raw * 2
                           if owner.mode == "not_ed25519" else SPKI_PREFIX + raw)
                    out = {"KeyId": body["KeyId"], "PublicKey": base64.b64encode(der).decode()}
                elif target == "TrentService.Sign":
                    sig = owner.key.sign(base64.b64decode(body["Message"]))
                    out = {"KeyId": body["KeyId"], "Signature": base64.b64encode(sig[:63] if owner.mode == "short_sig" else sig).decode()}
                else:
                    self.send_response(400); self.end_headers(); return
                data = json.dumps(out).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers()
                self.wfile.write(data)

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


DEAD_PROXY = {"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
              "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "NO_PROXY": "", "no_proxy": ""}


@unittest.skipUnless(HAVE, "the [sign] extra (cryptography) is not installed")
class TestKMSLocal(unittest.TestCase):
    def signer(self, kms):
        return KMSSigner("alias/test", "eu-south-1", access_key="AKIATESTTESTTESTTEST", secret_key="s" * 40,
                         endpoint=kms.url)

    def test_sign_end_to_end_with_a_dead_environment_proxy(self):
        # in a new interpreter whose environment holds the proxy from the start, as on a corporate network: urllib
        # builds its default opener once per process, so a proxy set later in this process would not be read
        kms = FakeKMS()
        code = ("import json, sys; from omega_cra_evol.kms import KMSSigner; "
                "s = KMSSigner('alias/test', 'eu-south-1', access_key='AKIATESTTESTTESTTEST', secret_key='s' * 40, endpoint=sys.argv[1]); "
                "print(json.dumps({'pub': s.public_key_hex, 'sig': s.sign(b'payload').hex()}))")
        env = {**os.environ, **DEAD_PROXY, "PYTHONPATH": ROOT}
        try:
            r = subprocess.run([sys.executable, "-c", code, kms.url], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
            out = json.loads(r.stdout)
            pub = kms.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(out["pub"], pub.hex())
            Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(out["sig"]), b"payload")   # raises if wrong
            self.assertEqual([c[0] for c in kms.calls], ["TrentService.GetPublicKey", "TrentService.Sign"])
            self.assertTrue(all(c[1].startswith("AWS4-HMAC-SHA256 Credential=AKIATESTTESTTESTTEST/") for c in kms.calls))
        finally:
            kms.close()

    def test_a_key_that_is_not_ed25519_is_refused(self):
        kms = FakeKMS("not_ed25519")
        try:
            with self.assertRaisesRegex(RuntimeError, "not Ed25519"):
                self.signer(kms)
        finally:
            kms.close()

    def test_a_signature_that_is_not_64_bytes_is_refused(self):
        kms = FakeKMS("short_sig")
        try:
            s = self.signer(kms)
            with self.assertRaisesRegex(RuntimeError, "not 64 bytes"):
                s.sign(b"payload")
        finally:
            kms.close()

    def test_a_non_loopback_http_endpoint_is_refused(self):
        with self.assertRaisesRegex(ValueError, "https"):
            KMSSigner("alias/test", "eu-south-1", access_key="AKIATESTTESTTESTTEST", secret_key="s" * 40,
                      endpoint="http://kms.example.com")


if __name__ == "__main__":
    unittest.main()

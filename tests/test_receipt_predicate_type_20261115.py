# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra verify-attestation`: the receipt's `predicate_type` is never a default (CHANGELOG, Unreleased; art14-filing v0.2
§5 amended 15/11/2026). On 15/11/2026 the receipt named `…/art14-filing/v0.1` for each of 270 envelopes of other tools,
156 of which declare another type (SLSA provenance v0.2 / v1, CycloneDX, cosign, VSA). Envelopes built here with those
predicate types: untrusted -> "not_evaluated"; trusted -> the declared type, refused with `predicate_type`."""
import base64
import importlib.util
import json
import os
import random
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from omega_cra_evol import art14_attest as A  # noqa: E402
from gen_art14_vectors import TEST_KEY_STRING, envelope, test_key  # noqa: E402

VD = os.path.join(ROOT, "spec", "art14-filing", "v0.2", "vectors")
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
OTHER_TYPES = ["https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom",
               "cosign.sigstore.dev/attestation/v1", "https://slsa.dev/verification_summary/v1", "https://spdx.dev/Document"]


def _ts():
    with open(os.path.join(VD, "trust_store.json"), encoding="utf-8") as f:
        return json.load(f)


def _verify(env):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(env, f)
    try:
        return A.verify_envelope(f.name, _ts())
    finally:
        os.unlink(f.name)


def _statement(t):
    return {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
            "predicateType": t, "predicate": {"buildType": "x"}}


def _raw(st):
    return json.dumps(st, separators=(",", ":")).encode()


class Untrusted(unittest.TestCase):
    def test_other_tools_types_are_not_evaluated(self):
        for t in OTHER_TYPES + [A.TYPE_URI, A.TYPE_URI_V02]:
            env = {"payloadType": A.PAYLOAD_TYPE, "payload": base64.b64encode(_raw(_statement(t))).decode(),
                   "signatures": [{"keyid": "", "sig": base64.b64encode(b"\0" * 64).decode()}]}
            with self.subTest(t=t):
                r = _verify(env)
                self.assertFalse(r["verified"])
                self.assertEqual(r["predicate_type"], "not_evaluated")      # an untrusted payload is never read

    def test_malformed_envelopes_are_not_evaluated(self):
        for env in ({}, {"payload": 1}, {"payloadType": "application/vnd.in-toto+json", "payload": "!!", "signatures": []},
                    {"payloadType": "text/plain", "payload": base64.b64encode(_raw(_statement(OTHER_TYPES[0]))).decode(), "signatures": []},
                    [], "x"):
            r = _verify(env)
            self.assertEqual(r["predicate_type"], "not_evaluated", env)

    def test_generated_untrusted_never_names_a_type(self):
        rnd = random.Random(42)
        for i in range(200):
            t = rnd.choice(OTHER_TYPES + [A.TYPE_URI, A.TYPE_URI_V02, None, 5, "x" * rnd.randrange(300)])
            st = _statement(t)
            env = {"payloadType": rnd.choice([A.PAYLOAD_TYPE, "application/json"]),
                   "payload": base64.b64encode(_raw(st)).decode(),
                   "signatures": [{"keyid": rnd.choice(["", "k", "test-signer"]), "sig": base64.b64encode(os.urandom(64)).decode()}]}
            self.assertEqual(_verify(env)["predicate_type"], "not_evaluated", i)


@unittest.skipUnless(HAVE_CRYPTO, "the envelope is signed: cryptography needed")
class Trusted(unittest.TestCase):
    def sign(self, raw):
        return envelope(raw, test_key(TEST_KEY_STRING))

    def test_declared_type_is_named_and_refused(self):
        for t in OTHER_TYPES:
            with self.subTest(t=t):
                r = _verify(self.sign(_raw(_statement(t))))
                self.assertTrue(r["trusted"])
                self.assertFalse(r["verified"])
                self.assertEqual(r["predicate_type"], t)
                self.assertIn("predicate_type", [x["code"] for x in r["reasons"]])

    def test_long_type_is_truncated(self):
        t = "https://example.org/" + "a" * 400
        self.assertEqual(_verify(self.sign(_raw(_statement(t))))["predicate_type"], t[:200])
        self.assertEqual(A.PREDICATE_TYPE_MAX, 200)

    def test_no_string_type_or_no_json_is_not_evaluated(self):
        for raw in (_raw(_statement(None)), _raw(_statement(["x"])), b"not json", b"[1]", b'{"predicateType": "a", "predicateType": "b"}'):
            with self.subTest(raw=raw[:40]):
                r = _verify(self.sign(raw))
                self.assertTrue(r["trusted"])
                self.assertEqual(r["predicate_type"], "not_evaluated")

    def test_defined_types_as_before(self):
        with open(os.path.join(VD, "valid_no_identifiers_without_drop.intoto.json"), encoding="utf-8") as f:
            r = _verify(json.load(f))
        self.assertEqual((r["verified"], r["predicate_type"]), (True, A.TYPE_URI_V02))


if __name__ == "__main__":
    unittest.main()

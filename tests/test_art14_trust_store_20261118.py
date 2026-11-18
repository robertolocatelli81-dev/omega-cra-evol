# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/art14-filing v0.1 §5, "The trust store is checked whole, before any signature", written before the
code.

An external review of 0.12.0, re-measured that day: `verify_envelope` checked a trust store key only when a signature
tried it, and stopped at the first broken one, so one envelope and one broken store gave two verdicts: an envelope
signed by the key of `z_good`, no keyid: `{z_good}` trusted; `{a_bad: "zz", z_good}` refused (`trusted_key_malformed`);
`{z_good, zz_bad: "zz"}` TRUSTED; with `keyid: "z_good"`, trusted with every store. The review proposed to skip the
broken key (`continue`); that would let a store that cannot be what its owner meant pass in silence (closed by
construction: refused, never skipped). Rule: a store with one broken key (not 64 lower-case hex, small order or
non-canonical, not a string, a name that is not a string) is refused whole, with a reason naming each broken key, then
`not_trusted`; nothing is tried.

Generative: every kind of broken key x placed before / after the good key in name order x every keyid form (the good
one, the broken one, absent, empty, unknown) x one or two broken keys. Positive control: the good store alone is
trusted with every keyid form that names it or none. On 4557a1f this file fails (measured, CHANGELOG 0.13.0)."""
import copy
import itertools
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol.art14_attest import verify_envelope  # noqa: E402
from omega_cra_evol.signing import weak_ed25519_key  # noqa: E402

V1 = os.path.join(ROOT, "spec", "art14-filing", "v0.1", "vectors")
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

IDENTITY = "01" + "00" * 31                                   # the neutral point: small order
ORDER_TWO = "ec" + "ff" * 30 + "7f"                           # y = p - 1: small order
BROKEN = {"not_hex": ("zz", "trusted_key_malformed"), "upper": (None, "trusted_key_malformed"),
          "short": (None, "trusted_key_malformed"), "long": (None, "trusted_key_malformed"),
          "identity": (IDENTITY, "weak_key"), "order_two": (ORDER_TWO, "weak_key"),
          "int": (7, "trusted_key_malformed"), "none": (None, "trusted_key_malformed"),
          "list": ([], "trusted_key_malformed"), "empty": ("", "trusted_key_malformed")}


class TrustStoreWhole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        with open(os.path.join(V1, "trust_store.json"), encoding="utf-8") as f:
            cls.good = json.load(f)["test-signer"]
        with open(os.path.join(V1, "valid_native_early_warning.intoto.json"), encoding="utf-8") as f:
            cls.env = json.load(f)
        cls.broken = {}
        for kind, (value, code) in BROKEN.items():
            if kind == "upper":
                value = cls.good.upper()
            elif kind == "short":
                value = cls.good[:-1]
            elif kind == "long":
                value = cls.good + "0"
            elif kind == "none":
                value = None
            cls.broken[kind] = (value, code)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def envelope(self, keyid):
        """the vector's valid envelope (signed by test-signer's key) with its signature's keyid set (keyid is not signed)"""
        e = copy.deepcopy(self.env)
        s = e["signatures"][0]
        s.pop("keyid", None)
        if keyid is not None:
            s["keyid"] = keyid
        p = os.path.join(self.td, f"e{len(os.listdir(self.td))}.intoto.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(e, f)
        return p

    def test_weak_keys_are_weak(self):
        self.assertTrue(weak_ed25519_key(IDENTITY))
        self.assertTrue(weak_ed25519_key(ORDER_TWO))
        self.assertFalse(weak_ed25519_key(self.good))

    @unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` to verify a signature (the control)")
    def test_control_good_store(self):
        for keyid in ("m_good", None, ""):
            r = verify_envelope(self.envelope(keyid), {"m_good": self.good})
            self.assertTrue(r["trusted"], (keyid, r["reasons"]))

    def test_one_broken_key_refuses_the_store_whatever_its_place_and_the_keyid(self):
        n = 0
        bad = []
        for (kind, (value, code)), name, keyid in itertools.product(
                self.broken.items(), ("a_bad", "zz_bad"), ("m_good", "BAD", None, "", "unknown")):
            store = {"m_good": self.good, name: value}
            kid = name if keyid == "BAD" else keyid
            r = verify_envelope(self.envelope(kid), store)
            codes = [x["code"] for x in r["reasons"]]
            n += 1
            if r["trusted"] or r["verified"] or codes != [code, "not_trusted"] or name not in r["reasons"][0]["detail"] \
                    or any(s.get("result") == "verified" for s in r["signatures"]):
                bad.append((kind, name, kid, r["trusted"], codes))
        self.assertEqual(n, 100)
        self.assertEqual(bad, [], f"{len(bad)} of {n}")

    def test_two_broken_keys_both_named(self):
        store = {"a_bad": "zz", "m_good": self.good, "zz_weak": IDENTITY}
        r = verify_envelope(self.envelope(None), store)
        self.assertEqual([x["code"] for x in r["reasons"]], ["trusted_key_malformed", "weak_key", "not_trusted"])
        self.assertIn("'a_bad'", r["reasons"][0]["detail"])
        self.assertIn("'zz_weak'", r["reasons"][1]["detail"])
        self.assertFalse(r["trusted"])

    def test_a_name_that_is_not_a_string(self):
        """a library caller may pass any dict (the CLI's load_trust_store already refuses this)"""
        r = verify_envelope(self.envelope(None), {"m_good": self.good, 3: self.good})
        self.assertEqual([x["code"] for x in r["reasons"]], ["trusted_key_malformed", "not_trusted"])
        self.assertFalse(r["trusted"])
        r = verify_envelope(self.envelope(None), ["m_good", self.good])
        self.assertEqual([x["code"] for x in r["reasons"]], ["trusted_key_malformed", "not_trusted"])

    def test_the_vector_receipt_is_unchanged(self):
        """small_order_trusted_key: one key, broken; the receipt of 0.8.0 (tests/fixtures/art14_v01_receipts_080) holds"""
        with open(os.path.join(V1, "trust_store_small_order.json"), encoding="utf-8") as f:
            store = json.load(f)
        r = verify_envelope(os.path.join(V1, "small_order_trusted_key.intoto.json"), store)
        self.assertEqual([x["code"] for x in r["reasons"]], ["weak_key", "not_trusted"])
        self.assertEqual(r["signatures"], [{"index": 0, "keyid": "test-signer", "result": "weak_key"}])


if __name__ == "__main__":
    unittest.main()

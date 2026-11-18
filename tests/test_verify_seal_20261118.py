# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/TIME_ANCHOR.md §10 (written before the code): `cra verify-seal`, the command that verifies the
long-term seals recorded in a ledger. Until 0.12.0 a seal was verified only when it was made or through the Python API.
Positive control: on c215a64 (before this code) every test here fails (no such command, exit 2)."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from local_tsa import HAVE_OPENSSL, LocalTsa  # noqa: E402

HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None


def cra(d, *args, path=None):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ROOT
    env["HOME"] = d
    if path is not None:
        env["PATH"] = path
    return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", *args], cwd=d, capture_output=True, text=True,
                          env=env, timeout=180)


@unittest.skipUnless(HAVE_CRYPTO, "a seal is signed: cryptography needed")
class VerifySeal(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.led = os.path.join(self.d, "l.jsonl")
        self.key = os.path.join(self.d, "k.key")
        self.assertEqual(cra(self.d, "keygen", self.key).returncode, 0)
        self.base = ["--ledger", self.led, "--product", "p", "--version", "1", "--tip-key", self.key]
        r = cra(self.d, "vuln", *self.base, "--id", "CVE-2026-1", "--aware", "2026-09-01T00:00:00Z")
        self.assertEqual(r.returncode, 0, r.stderr)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def pack(self, name="pack.json"):
        r = cra(self.d, "pack", *self.base, "--out", os.path.join(self.d, name))
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)["pack_sha3"]

    def vs(self, *extra, **kw):
        r = cra(self.d, "verify-seal", "--ledger", self.led, *extra, **kw)
        self.assertNotIn("Traceback", r.stderr)
        return r, (json.loads(r.stdout) if r.stdout.strip() else None)

    def lines(self):
        with open(self.led, "rb") as f:
            return f.read()

    def test_no_seal_and_asserted_seal(self):
        ps = self.pack()
        r, out = self.vs()
        self.assertEqual((r.returncode, out["reasons"]), (1, ["no seal in this ledger"]))
        self.assertEqual(cra(self.d, "seal", *self.base, "--pack-sha3", ps).returncode, 0)
        before = self.lines()
        r, out = self.vs()
        self.assertEqual(r.returncode, 0, r.stdout)
        s = out["seals"][0]
        self.assertEqual((out["ok"], s["pack_sha3"], s["anchored_pack"], s["records_in_ledger"], s["sealer"]),
                         (True, ps, True, 1, "not pinned"))
        self.assertTrue(s["verify"]["temporal_trust"].startswith("ASSUMED"))        # no --tsa-cert: the time is not verified
        self.assertEqual(self.lines(), before)                                      # records nothing
        r, out = self.vs("--pack-sha3", "0" * 64)
        self.assertEqual((r.returncode, out["reasons"]), (1, ["no seal of this digest in the ledger"]))
        r, out = self.vs("--pack-sha3", ps)
        self.assertEqual(r.returncode, 0)
        for bad in (["--pack-sha3", "xyz"], ["--sealer-pubkey", "AB" * 32], ["--at", "yesterday"],
                    ["--tsa-cert", os.path.join(self.d, "absent.pem")]):
            r = cra(self.d, "verify-seal", "--ledger", self.led, *bad)
            self.assertEqual(r.returncode, 2, bad)
        r, out = cra(self.d, "verify-seal", "--ledger", os.path.join(self.d, "absent.jsonl")), None
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(os.path.join(self.d, "absent.jsonl")))

    def test_sealer_pin(self):
        ps = self.pack()
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps)
        pub = json.loads(r.stdout)["seal"]["records"][0]["pub"]
        r, out = self.vs("--sealer-pubkey", pub)
        self.assertEqual((r.returncode, out["seals"][0]["sealer"]), (0, "pinned"))
        r, out = self.vs("--sealer-pubkey", "0" * 64)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not in trusted_pubs", " ".join(out["seals"][0]["verify"]["reasons"]))

    def test_the_last_seal_record_of_a_digest_is_the_one_evaluated(self):
        """a renewal is a new record holding the whole chain: the chain of two records is verified, not the first"""
        ps = self.pack()
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps)
        self.assertEqual(r.returncode, 0, r.stderr)
        prev = os.path.join(self.d, "prev.json")
        with open(prev, "w", encoding="utf-8") as f:
            json.dump(json.loads(r.stdout)["seal"], f)
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--renew", prev)
        self.assertIn(r.returncode, (0, 1), r.stderr)        # recorded; a renewal on asserted times says so (exit 1)
        r, out = self.vs()
        s = out["seals"][0]
        self.assertEqual((len(out["seals"]), s["records_in_ledger"], s["verify"]["chain_len"]), (1, 2, 2))
        with open(self.led, encoding="utf-8") as f:
            idx = [json.loads(ln)["idx"] for ln in f if '"cra_longterm_seal"' in ln]
        self.assertEqual(s["ledger_idx"], idx[-1])

    def test_a_tampered_ledger_evaluates_no_seal(self):
        ps = self.pack()
        self.assertEqual(cra(self.d, "seal", *self.base, "--pack-sha3", ps).returncode, 0)
        raw = self.lines()
        i = raw.index(b'"sig"')
        j = raw.index(b'"', i + 7) + 1                       # first hex character of the signature of the seal record
        with open(self.led, "wb") as f:
            f.write(raw[:j] + (b"0" if raw[j:j + 1] != b"0" else b"1") + raw[j + 1:])
        r, out = self.vs()
        self.assertEqual(r.returncode, 1)
        self.assertEqual((out["ledger"]["chain_ok"], out["seals"]), (False, []))

    def test_the_policy_instant(self):
        ps = self.pack()
        self.assertEqual(cra(self.d, "seal", *self.base, "--pack-sha3", ps).returncode, 0)
        r, out = self.vs("--at", "2030-01-01T00:00:00Z")
        self.assertEqual(r.returncode, 0, r.stdout)
        r, out = self.vs("--at", "2036-01-01T00:00:01Z")      # NIST IR 8547: Ed25519 disallowed after 2035
        self.assertEqual(r.returncode, 1)
        self.assertIn("broken at now", " ".join(out["seals"][0]["verify"]["reasons"]))

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl (the local TSA)")
    def test_rfc3161_seal_verified_against_the_pinned_tsa(self):
        tsa = LocalTsa(os.path.join(self.d, "tsa"))
        other = LocalTsa(os.path.join(self.d, "tsa2"))
        ps = self.pack()
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--print-imprint")
        tok = tsa.token(json.loads(r.stdout)["imprint_hex"])
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64", tok, "--tsa-cert", tsa.ca)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r, out = self.vs("--tsa-cert", tsa.ca)
        self.assertEqual(r.returncode, 0, r.stdout)
        v = out["seals"][0]["verify"]
        self.assertEqual((v["temporal_trust"], [x["ok"] for x in v["time_anchor_log"]]), ("verified", [True]))
        r, out = self.vs()                                    # the same seal without a pin: not verified, said so
        self.assertEqual(r.returncode, 0)
        self.assertTrue(out["seals"][0]["verify"]["temporal_trust"].startswith("ASSUMED"))
        r, out = self.vs("--tsa-cert", other.ca)              # another TSA's CA: the time is not attested
        self.assertEqual(r.returncode, 1, r.stdout)
        v = out["seals"][0]["verify"]
        self.assertTrue(v["temporal_trust"].startswith("NOT verified"))
        self.assertEqual([x["ok"] for x in v["time_anchor_log"]], [False])
        # an asserted seal of a second pack next to it: with --tsa-cert it is not attested, and it is named
        ps2 = self.pack("pack2.json")
        self.assertEqual(cra(self.d, "seal", *self.base, "--pack-sha3", ps2).returncode, 0)
        r, out = self.vs("--tsa-cert", tsa.ca)
        self.assertEqual(r.returncode, 1)
        self.assertEqual({s["pack_sha3"]: s["verify"]["ok"] for s in out["seals"]}, {ps: True, ps2: False})
        r, out = self.vs("--tsa-cert", tsa.ca, "--pack-sha3", ps)
        self.assertEqual(r.returncode, 0)
        # no openssl on PATH: "not checked", exit 74, never a refusal
        empty = os.path.join(self.d, "emptybin")
        os.makedirs(empty)
        r, out = self.vs("--tsa-cert", tsa.ca, "--pack-sha3", ps, path=empty)
        self.assertEqual(r.returncode, 74, r.stdout + r.stderr)
        self.assertEqual(out["seals"][0]["verify"]["temporal_trust"], "not checked")


if __name__ == "__main__":
    unittest.main()

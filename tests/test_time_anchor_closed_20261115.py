# SPDX-License-Identifier: AGPL-3.0-or-later
"""spec/TIME_ANCHOR.md §5 closed for the record and for the pin (NEMESIS review of 15/11/2026).

On 3b228c2 the trust function answered "verified" for an anchored record that also carried a field the token does not
stamp (re-signed by the sealer), a `token_sha3` that is not the token's digest or absent, and a `t` written `" 1.0\\n"`,
`"+1.0"`, `"1_0.0"` or without `.0`; a pinned file that only began with 0x30 was accepted, and openssl, unable to load
it, refused every token as `signature_invalid` (with a good pin beside it, `not_issued_by_pinned_tsa`); an unreadable
pinned file was a PermissionError; `cra seal --tsa-cert` recorded a seal it then refused (exit 1: a retry records it
twice), also for an asserted seal; `verify` raised TypeError on a record whose `hash` is a list."""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import _streams  # noqa: E402
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from local_tsa import HAVE_OPENSSL, LocalTsa  # noqa: E402
from omega_cra_evol.longterm import LongTermEvidence, Signer, register_algorithm  # noqa: E402
from omega_cra_evol import time_anchor as TA  # noqa: E402

register_algorithm("test-closed", gen=lambda: ("sk", "pk-" + os.urandom(4).hex()), sign=lambda sk, m: m.hex(),
                   verify=lambda pub, sig, m: sig == m.hex())
D = hashlib.sha3_256(b"closed").hexdigest()


def resign(lte, i):
    rec = lte.records[i]
    rec["sig"] = lte._msg(i, rec, rec.get("hash", "sha3-256")).hex()


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl (the local TSA)")
class Closed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.tsa = LocalTsa(os.path.join(cls.td, "a"))
        cls.lte = LongTermEvidence(D)
        for _ in range(2):
            s = Signer("test-closed")
            cls.lte.seal(s, None, ts_source="rfc3161", token_b64=cls.tsa.token(cls.lte.anchor_imprint(s)))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def answer(self, lte, pins=None):
        fn = TA.make_timestamp_trust_fn(lte, pins or [self.tsa.ca])
        return [fn(r) for r in lte.records], [e["reason"] for e in fn.log]

    def altered(self, change):
        lte = LongTermEvidence(D, records=copy.deepcopy(self.lte.records))
        change(lte.records[1])
        resign(lte, 1)
        return lte

    def test_positive_control(self):
        self.assertEqual(self.answer(self.lte), ([True, True], [None, None]))

    def test_unknown_field_refused(self):
        for key in ("ghost", "t2", "token_b64x", "Anchor", ""):
            with self.subTest(key):
                self.assertEqual(self.answer(self.altered(lambda r: r.__setitem__(key, "x"))),
                                 ([True, False], [None, "unknown_field"]))

    def test_token_sha3_must_match(self):
        self.assertEqual(self.answer(self.altered(lambda r: r.__setitem__("token_sha3", "00" * 32)))[1][1],
                         "token_sha3_mismatch")
        self.assertEqual(self.answer(self.altered(lambda r: r.pop("token_sha3")))[1][1], "token_sha3_mismatch")

    def test_t_is_the_string_of_section_3(self):
        t = self.lte.records[1]["t"]
        self.assertTrue(t.endswith(".0"))
        for v in (" " + t + "\n", "+" + t, t[:2] + "_" + t[2:], t[:-2], t + "0"):
            with self.subTest(v):
                self.assertEqual(self.answer(self.altered(lambda r: r.__setitem__("t", v)))[1][1], "t_not_gen_time")

    def test_pin_shape(self):
        bad = os.path.join(self.td, "junk.pem")
        with open(bad, "wb") as f:
            f.write(b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n")
        for pins in ([bad], [self.tsa.ca, bad], [b"\x30\x03\x02\x01\x01"], [self.tsa.ca, b"\x30\x00"]):
            with self.assertRaises(ValueError):
                TA.make_timestamp_trust_fn(self.lte, pins)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads a 000 file")
    def test_unreadable_pin_is_a_value_error(self):
        u = os.path.join(self.td, "u.pem")
        shutil.copy(self.tsa.ca, u)
        _streams.deny_reads(self, u)   # Windows: an ACL entry, the mode does not stop a read there
        with self.assertRaises(ValueError):
            TA.make_timestamp_trust_fn(self.lte, [u])

    def test_token_base64_is_strict(self):
        tok = self.lte.records[1]["token_b64"]
        for bad in (tok[:8] + "\n" + tok[8:], tok + "!", " " + tok):
            with self.subTest(repr(bad[:12])):
                lte = self.altered(lambda r: r.update(token_b64=bad, token_sha3=hashlib.sha3_256(bad.encode()).hexdigest()))
                self.assertEqual(self.answer(lte)[1][1], "token_not_base64")
        from omega_cra_evol.rfc3161_token import TokenRefused
        s = Signer("test-closed")
        fresh = LongTermEvidence(D)
        good = self.tsa.token(fresh.anchor_imprint(s))
        with self.assertRaises(TokenRefused):
            fresh.seal(s, None, ts_source="rfc3161", token_b64=good[:8] + "\n" + good[8:])

    def test_gen_time_form(self):
        """spec §3 / RFC 3161 §2.4.2: a fraction without trailing zero, a real calendar time; fractional genTime verifies."""
        import base64
        from omega_cra_evol.rfc3161_token import TokenRefused, rfc3161_tstinfo
        frac = LocalTsa(os.path.join(self.td, "frac"))
        with open(frac.j("tsa.cnf")) as f:
            cnf = f.read()
        with open(frac.j("tsa.cnf"), "w") as f:
            f.write(cnf.replace("accuracy = secs:1\n", "accuracy = secs:1\nclock_precision_digits = 3\n"))
        for _attempt in range(5):   # a genTime on a whole second carries no fraction (RFC 3161 §2.4.2): try again
            lte = LongTermEvidence(D)
            for _ in range(2):
                s = Signer("test-closed")
                lte.seal(s, None, ts_source="rfc3161", token_b64=frac.token(lte.anchor_imprint(s)))
            gens = [rfc3161_tstinfo(base64.b64decode(r["token_b64"]))[2] for r in lte.records]
            if all("." in g for g in gens):
                break
        if not all("." in g for g in gens):
            self.skipTest("this openssl wrote no fraction")
        self.assertEqual(self.answer(lte, [frac.ca]), ([True, True], [None, None]))
        self.assertNotEqual(lte.records[1]["t"], repr(float(int(float(lte.records[1]["t"])))))
        raw = base64.b64decode(lte.records[1]["token_b64"])
        g = gens[1].encode()
        for bad in (g[:-2] + b"0Z", g[:4] + b"13" + g[6:], g[:8] + b"25" + g[10:]):
            if len(bad) != len(g) or bad == g:
                continue
            with self.subTest(bad):
                with self.assertRaises(TokenRefused):
                    rfc3161_tstinfo(raw.replace(g, bad, 1))

    def test_hash_of_another_type_is_malformed_not_a_crash(self):
        lte = LongTermEvidence(D, records=copy.deepcopy(self.lte.records))
        lte.records[1]["hash"] = ["x"]
        v = lte.verify(now=1.0)
        self.assertFalse(v["ok"])
        self.assertIn("malformed", v["reasons"][0])


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl (the local TSA)")
class SealRecordsNothingItRefuses(unittest.TestCase):
    def run_cra(self, *args, cwd):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONPATH"] = ROOT
        return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", *args], cwd=cwd, capture_output=True, text=True,
                              env=env, timeout=120)

    def test_refusals_record_nothing(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("a seal is signed: cryptography needed")
        d = tempfile.mkdtemp()
        try:
            a, b = LocalTsa(os.path.join(d, "a")), LocalTsa(os.path.join(d, "b"))
            key, led = os.path.join(d, "k.key"), os.path.join(d, "l.jsonl")
            self.assertEqual(self.run_cra("keygen", key, cwd=d).returncode, 0)
            base = ["--ledger", led, "--product", "p", "--version", "1", "--tip-key", key]
            self.assertEqual(self.run_cra("vuln", *base, "--id", "CVE-2026-1", "--aware", "2026-09-01T00:00:00Z",
                                          cwd=d).returncode, 0)
            ps = json.loads(self.run_cra("pack", *base, "--out", os.path.join(d, "p.json"), cwd=d).stdout)["pack_sha3"]
            with open(led, "rb") as f:
                before = f.read()
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--tsa-cert", a.ca, cwd=d)       # asserted + pin
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            imp = json.loads(self.run_cra("seal", *base, "--pack-sha3", ps, "--print-imprint", cwd=d).stdout)["imprint_hex"]
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64", b.token(imp),
                             "--tsa-cert", a.ca, cwd=d)                                          # another TSA's token
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertFalse(json.loads(r.stdout)["sealed"])
            with open(led, "rb") as f:
                self.assertEqual(f.read(), before)                                           # nothing recorded
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64", a.token(imp),
                             "--tsa-cert", a.ca, cwd=d)                                          # the pinned TSA
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["verify"]["temporal_trust"], "verified")
            self.assertEqual([e["reason"] for e in out["verify"]["time_anchor_log"]], [None])
        finally:
            shutil.rmtree(d, ignore_errors=True)


class AppendStateBoundToTheChain(unittest.TestCase):
    """NEMESIS 15/11/2026: a state file whose hash matches the ledger's bytes but whose `last`, `n` or `first` is another
    made the writer append an entry with that prev_hash and idx: a chain broken for good. The state is now used only if
    the ledger's first and last entries agree with it; otherwise the whole ledger is read, as without a state file."""
    def test_tampered_state_is_not_used(self):
        from omega_cra_evol import ledger as LG
        for field, value in (("last", "ab" * 32), ("n", 7), ("first", "cd" * 32), ("n", 1)):
            with self.subTest(field=field, value=value):
                d = tempfile.mkdtemp()
                try:
                    p = os.path.join(d, "l.jsonl")
                    led = LG.Ledger(p)
                    for i in range(3):
                        led.append({"k": i})
                    st_path = p + LG.STATE_SUFFIX
                    with open(st_path, encoding="utf-8") as f:
                        st = json.load(f)
                    st[field] = value
                    with open(st_path, "w", encoding="utf-8") as f:
                        json.dump(st, f)
                    led.append({"k": "after"})
                    with open(p, encoding="utf-8") as f:
                        es = [json.loads(x) for x in f]
                    self.assertEqual([e["idx"] for e in es], [0, 1, 2, 3])
                    self.assertEqual(es[3]["prev_hash"], es[2]["self_hash"])
                finally:
                    shutil.rmtree(d, ignore_errors=True)

    def test_untampered_state_is_used(self):
        from unittest import mock
        from omega_cra_evol import ledger as LG
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "l.jsonl")
            led = LG.Ledger(p)
            for i in range(5):
                led.append({"k": i})
            seen = []
            real = LG._tail_state
            with mock.patch.object(LG, "_tail_state", lambda f, start=None: (seen.append(start), real(f, start))[1]):
                led.append({"k": "x"})
            self.assertIsNotNone(seen[0])
            self.assertEqual(seen[0]["n"], 5)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class KmsEndpointScheme(unittest.TestCase):
    """NEMESIS 15/11/2026: any scheme towards a loopback host passed the custom endpoint check (file://localhost/...,
    ftp://localhost/...), and an I/O was attempted with it."""
    def test_only_https_or_loopback_http(self):
        from unittest import mock
        from omega_cra_evol import kms
        with mock.patch.object(kms.KMSSigner, "_read_pubkey", lambda self: "00" * 32):
            def make(ep):
                return kms.KMSSigner("k", region="eu-west-1", access_key="AKIAEXAMPLE", secret_key="x", endpoint=ep)
            for ep in ("file://localhost/etc/hostname", "ftp://localhost/x", "gopher://localhost/", "http://127.0.0.2:4566",
                       "http://kms.example", "https://", "data:,x"):
                with self.subTest(ep):
                    with self.assertRaises(ValueError):
                        make(ep)
            for ep in ("http://localhost:4566", "http://127.0.0.1:4566", "http://[::1]:4566", "https://kms.example"):
                make(ep)


if __name__ == "__main__":
    unittest.main()

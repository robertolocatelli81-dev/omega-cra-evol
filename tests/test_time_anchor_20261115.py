# SPDX-License-Identifier: AGPL-3.0-or-later
"""spec/TIME_ANCHOR.md (cra-lta-time-anchor/1): what the RFC 3161 token of a seal record stamps, and the
`timestamp_trust_fn` that checks it against pinned TSA certificates (omega_cra_evol.time_anchor). Proposed by Athena's
review of 15/11/2026 (prototype p5_timestamp_trust.py).

Before this file the package shipped no `timestamp_trust_fn` and its tests injected `lambda r: True`: the positive control
of this file shows that oracle accepting a record whose "token" is `not base64!`. The function here must accept a chain
whose tokens stamp each record under the pinned TSA, and refuse, each with its closed reason: a pin of another TSA, a token
over another digest, over the bare evidence digest (the shape of 0.9.0-0.11.1), from another record or another chain, a
token whose signature was altered, a `t` that is not the token's genTime, an asserted record, a record outside the chain.
Generative: every own field of a record changed, single-bit flips of the token, chains of random length and order."""
import base64
import hashlib
import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from local_tsa import HAVE_OPENSSL, LocalTsa  # noqa: E402
from omega_cra_evol.longterm import ANCHOR, LongTermEvidence, Signer, register_algorithm  # noqa: E402
from omega_cra_evol.rfc3161_token import TokenRefused  # noqa: E402
from omega_cra_evol import time_anchor as TA  # noqa: E402

# a signature scheme of the test only (the trust function does not look at signatures): sign = the message's hex
register_algorithm("test-anchor", gen=lambda: ("sk", "pk-" + os.urandom(4).hex()), sign=lambda sk, m: m.hex(),
                   verify=lambda pub, sig, m: sig == m.hex())
D = hashlib.sha3_256(b"evidence").hexdigest()


def chain(tsa, n=2, digest=D, alg="sha256", signer=None):
    lte = LongTermEvidence(digest)
    for _ in range(n):
        s = signer or Signer("test-anchor")
        lte.seal(s, None, ts_source="rfc3161", token_b64=tsa.token(lte.anchor_imprint(s, tsa_hash=alg), alg=alg))
    return lte


def _lines(p):
    with open(p, encoding="utf-8") as f:
        return sum(1 for _ in f)


def answers(lte, pins):
    fn = TA.make_timestamp_trust_fn(lte, pins)
    return [fn(r) for r in lte.records], [e["reason"] for e in fn.log]


class AnchorImprintKnownAnswers(unittest.TestCase):
    """spec/TIME_ANCHOR.md §2 computed here from its text alone (hashlib + json), and frozen: a change of the binding is a
    new anchor identifier, never the same one with other bytes."""
    OWN = {"alg": "ed25519", "anchor": ANCHOR, "ephemeral_key": False, "hash": "sha3-256", "pub": "11" * 32, "rehash": "",
           "ts_source": "rfc3161"}

    @staticmethod
    def by_the_text(records, own, h):
        body = json.dumps([D, records, own], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return h(b"cra-lta-time-anchor/1\n" + body.encode()).hexdigest()

    def test_known_answers(self):
        lte = LongTermEvidence(D)
        self.assertEqual(lte.anchor_imprint_bytes(0, self.OWN, "sha256").hex(),
                         "511d01c72a396d83f3d6a9d7ad4a126ce3bbc01520f2f2134b446b666bd3d7d9")
        self.assertEqual(lte.anchor_imprint_bytes(0, self.OWN, "sha3-256").hex(),
                         "93bf3734dba8c666bb3f5b7e539d4f18440e7f87932c051bf581423e7e926b4f")
        prev = {"alg": "ed25519", "t": "1.0", "sig": "00"}
        lte.records.append(prev)
        got = lte.anchor_imprint_bytes(1, dict(self.OWN, t="9.0", token_b64="x", sig="y"), "sha256").hex()   # not own fields
        self.assertEqual(got, "6551104d24ac147907e2a347d4694c96db5773869aa5879e1292cb8c57f816cb")
        self.assertEqual(got, self.by_the_text([prev], self.OWN, hashlib.sha256))
        self.assertEqual(LongTermEvidence(D).anchor_imprint_bytes(0, self.OWN, "sha3-256").hex(),
                         self.by_the_text([], self.OWN, hashlib.sha3_256))
        with self.assertRaises(ValueError):
            lte.anchor_imprint_bytes(0, self.OWN, "sha512")


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl (the local TSA and the signature check)")
class TimeAnchor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.tsa, cls.other = LocalTsa(os.path.join(cls.td, "a")), LocalTsa(os.path.join(cls.td, "b"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def test_positive_one_record_and_a_renewal_chain(self):
        for alg in ("sha256", "sha3-256"):
            for n in (1, 3):
                lte = chain(self.tsa, n, alg=alg)
                self.assertEqual(answers(lte, [self.tsa.ca]), ([True] * n, [None] * n), (alg, n))
                self.assertEqual(lte.records[-1]["anchor"], ANCHOR)
                v = lte.verify(now=1.9e9, timestamp_trust_fn=TA.make_timestamp_trust_fn(lte, [self.tsa.ca]))
                self.assertEqual(v["temporal_trust"], "verified", v)
        self.assertEqual(answers(chain(self.tsa, 1), [self.tsa.j("tsa.crt")])[0], [True])      # the TSA's own certificate

    def test_positive_control_the_old_oracle_accepts_garbage(self):
        lte = LongTermEvidence(D)
        lte.records.append({"alg": "test-anchor", "pub": "pk", "sig": "00", "t": "1.0", "ts_source": "rfc3161",
                            "token_b64": "not base64!", "anchor": ANCHOR})
        self.assertEqual(lte.verify(now=2.0, timestamp_trust_fn=lambda r: True)["temporal_trust"], "verified")
        self.assertEqual(answers(lte, [self.tsa.ca]), ([False], ["token_not_base64"]))

    def test_another_tsa_pinned(self):
        self.assertEqual(answers(chain(self.tsa, 2), [self.other.ca]), ([False, False], ["not_issued_by_pinned_tsa"] * 2))
        self.assertEqual(answers(chain(self.tsa, 1), [self.other.ca, self.tsa.ca])[0], [True])      # one of several pins

    def test_tokens_that_stamp_something_else(self):
        s = Signer("test-anchor")
        cases = {
            "another digest": self.tsa.token("00" * 32),
            "the bare evidence digest, sha3": self.tsa.token(D, alg="sha3-256"),
            "the anchor of another chain": self.tsa.token(LongTermEvidence("11" * 32).anchor_imprint(s)),
            "the anchor of another signer": self.tsa.token(LongTermEvidence(D).anchor_imprint(Signer("test-anchor"))),
        }
        for name, tok in cases.items():
            with self.assertRaises(TokenRefused, msg=name):            # refused at seal ...
                LongTermEvidence(D).seal(s, None, ts_source="rfc3161", token_b64=tok)
            lte = LongTermEvidence(D)                                  # ... and by the function, on a record built by hand
            own = {"alg": "test-anchor", "anchor": ANCHOR, "ephemeral_key": True, "hash": "sha3-256", "pub": s.pub,
                   "rehash": "", "ts_source": "rfc3161"}
            lte.records.append(dict(own, t=self._t(tok), token_b64=tok, sig="00"))
            self.assertEqual(answers(lte, [self.tsa.ca]), ([False], ["imprint_mismatch"]), name)

    def _t(self, tok):
        from omega_cra_evol.rfc3161_token import gen_time_seconds, rfc3161_tstinfo
        return repr(gen_time_seconds(rfc3161_tstinfo(base64.b64decode(tok))[2]))

    def test_a_record_sealed_before_the_anchor_is_digest_only(self):
        lte = chain(self.tsa, 1)
        rec = lte.records[0]
        del rec["anchor"]
        self.assertEqual(answers(lte, [self.tsa.ca]), ([False], ["digest_only_binding"]))
        rec["anchor"] = "cra-lta-time-anchor/2"
        self.assertEqual(answers(lte, [self.tsa.ca]), ([False], ["anchor_unknown"]))

    def test_a_token_moved_to_another_record_or_chain(self):
        a, b = chain(self.tsa, 2), chain(self.tsa, 2)
        a.records[1]["token_b64"] = a.records[0]["token_b64"]           # the first record's token on the renewal
        self.assertEqual(answers(a, [self.tsa.ca]), ([True, False], [None, "imprint_mismatch"]))
        b.records[0]["token_b64"] = chain(self.tsa, 1).records[0]["token_b64"]   # a token of another chain's first record
        self.assertEqual(answers(b, [self.tsa.ca]), ([False, False], ["imprint_mismatch"] * 2))   # and the renewal over it

    def test_t_is_the_tokens_gen_time(self):
        lte = chain(self.tsa, 1)
        for bad in (repr(float(lte.records[0]["t"]) + 3600), repr(float(lte.records[0]["t"]) + 0.001), "x", None):
            r = json.loads(json.dumps(lte.to_dict()))
            r["records"][0]["t"] = bad
            x = LongTermEvidence.from_dict(r)
            self.assertEqual(answers(x, [self.tsa.ca]), ([False], ["t_not_gen_time"]), bad)
        s = Signer("test-anchor")
        tok = self.tsa.token(LongTermEvidence(D).anchor_imprint(s))
        with self.assertRaises(TokenRefused):
            LongTermEvidence(D).seal(s, 1.0, ts_source="rfc3161", token_b64=tok)       # a t that is not genTime

    def test_altered_signature(self):
        lte = chain(self.tsa, 1)
        der = bytearray(base64.b64decode(lte.records[0]["token_b64"])); der[-1] ^= 1
        lte.records[0]["token_b64"] = base64.b64encode(bytes(der)).decode()
        self.assertEqual(answers(lte, [self.tsa.ca]), ([False], ["signature_invalid"]))

    def test_asserted_and_outside_the_chain(self):
        lte = LongTermEvidence(D)
        lte.seal(Signer("test-anchor"), 5.0)
        self.assertEqual(answers(lte, [self.tsa.ca]), ([False], ["ts_source_not_rfc3161"]))
        fn = TA.make_timestamp_trust_fn(lte, [self.tsa.ca])
        self.assertFalse(fn(dict(lte.records[0])))                       # an equal copy is not the chain's record
        self.assertEqual(fn.log[-1]["reason"], "record_not_in_chain")

    def test_token_only_and_response_both_read(self):
        s = Signer("test-anchor")
        lte = LongTermEvidence(D)
        lte.seal(s, None, ts_source="rfc3161", token_b64=self.tsa.token(lte.anchor_imprint(s), token_only=True))
        self.assertEqual(answers(lte, [self.tsa.ca])[0], [True])

    def test_generative_every_own_field_changed(self):
        lte = chain(self.tsa, 2)
        variants = {"alg": "ed25519", "anchor": ANCHOR + "x", "ephemeral_key": False, "hash": "sha2-512", "pub": "pk-x",
                    "rehash": "ab" * 32, "ts_source": "ots"}
        for i in range(2):
            for k, v in variants.items():
                x = LongTermEvidence.from_dict(json.loads(json.dumps(lte.to_dict())))
                x.records[i][k] = v
                ok, reasons = answers(x, [self.tsa.ca])
                self.assertFalse(ok[i], (i, k))
                if i == 0:
                    self.assertFalse(ok[1], (i, k, "the renewal stamps record 0 whole"))

    def test_generative_token_bit_flips(self):
        lte = chain(self.tsa, 1)
        raw = base64.b64decode(lte.records[0]["token_b64"])
        rnd = random.Random(61)
        accepted = 0
        for _ in range(200):
            b = bytearray(raw)
            i = rnd.randrange(len(b)); b[i] ^= 1 << rnd.randrange(8)
            x = LongTermEvidence.from_dict(json.loads(json.dumps(lte.to_dict())))
            x.records[0]["token_b64"] = base64.b64encode(bytes(b)).decode()
            ok, reasons = answers(x, [self.tsa.ca])
            self.assertIn(reasons[0], TA.REASONS + (None,))
            accepted += ok[0]
            if ok[0]:   # only bytes outside the signed content may change: the TSTInfo read must be the same
                from omega_cra_evol.rfc3161_token import rfc3161_tstinfo
                self.assertEqual(rfc3161_tstinfo(bytes(b)), rfc3161_tstinfo(raw), i)
        print(f"  200 single-bit flips of a token: {accepted} accepted (outside the signed content)")

    def test_generative_truncations_and_junk(self):
        lte = chain(self.tsa, 1)
        raw = base64.b64decode(lte.records[0]["token_b64"])
        rnd = random.Random(15)
        junk = [raw[:k] for k in range(len(raw))] + [raw + b"\x00"] + \
               [bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 64))) for _ in range(300)]
        for b in junk:
            x = LongTermEvidence.from_dict(json.loads(json.dumps(lte.to_dict())))
            x.records[0]["token_b64"] = base64.b64encode(b).decode()
            ok, reasons = answers(x, [self.tsa.ca])
            self.assertEqual(ok, [False], b.hex()[:40])
            self.assertIn(reasons[0], ("token_missing", "token_malformed", "imprint_mismatch"), b.hex()[:40])
        for bad in ("", None, 5, "QUJD\n", "QUJD===", "é"):
            x = LongTermEvidence.from_dict(json.loads(json.dumps(lte.to_dict())))
            x.records[0]["token_b64"] = bad
            self.assertEqual(answers(x, [self.tsa.ca])[0], [False], repr(bad))

    def test_openssl_absent_is_not_a_refusal(self):
        lte = chain(self.tsa, 1)
        fn = TA.make_timestamp_trust_fn(lte, [self.tsa.ca])
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(TA.TimeAnchorNotRun):
                fn(lte.records[0])

    def test_the_pin_is_required(self):
        lte = chain(self.tsa, 1)
        for bad in ([], (), None, "ca.pem", b"x", [os.path.join(self.td, "absent.pem")], [b"not a certificate"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TA.make_timestamp_trust_fn(lte, bad)
        with open(self.tsa.ca, "rb") as f:
            pem = f.read()
        der = base64.b64decode(b"".join(pem.split(b"-----")[2].split()))
        self.assertEqual(answers(lte, [pem])[0], [True])
        self.assertEqual(answers(lte, [der])[0], [True])


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl (the local TSA)")
class SealCommand(unittest.TestCase):
    def run_cra(self, *args, cwd):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONPATH"] = ROOT
        return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", *args], cwd=cwd, capture_output=True, text=True,
                              env=env, timeout=120)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "a seal is signed: cryptography needed")
    def test_print_imprint_then_seal_then_verified(self):
        d = tempfile.mkdtemp()
        try:
            tsa = LocalTsa(os.path.join(d, "tsa"))
            key = os.path.join(d, "k.key")
            self.assertEqual(self.run_cra("keygen", key, cwd=d).returncode, 0)
            led = os.path.join(d, "l.jsonl")
            base = ["--ledger", led, "--product", "p", "--version", "1", "--tip-key", key]
            r = self.run_cra("vuln", *base, "--id", "CVE-2026-1", "--aware", "2026-09-01T00:00:00Z", cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = self.run_cra("pack", *base, "--out", os.path.join(d, "pack.json"), cwd=d)
            ps = json.loads(r.stdout)["pack_sha3"]
            n0 = _lines(led)
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--print-imprint", cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr)
            imp = json.loads(r.stdout)["imprint_hex"]
            self.assertEqual(_lines(led), n0)                       # printing records nothing
            r = self.run_cra("seal", *base[:-2], "--pack-sha3", ps, "--print-imprint", cwd=d)
            self.assertEqual(r.returncode, 2)                                      # no sealing key: usage error
            tok = tsa.token(imp)
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64", tok,
                             "--tsa-cert", tsa.ca, cwd=d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["verify"]["temporal_trust"], "verified")
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64", tsa.token(D),
                             cwd=d)
            self.assertEqual(r.returncode, 1)                                      # a token for another imprint
            self.assertFalse(json.loads(r.stdout)["sealed"])
            r = self.run_cra("seal", *base, "--pack-sha3", ps, "--tsa-cert", os.path.join(d, "absent.pem"), cwd=d)
            self.assertEqual(r.returncode, 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

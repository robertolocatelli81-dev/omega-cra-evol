# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/art14-filing v0.1 §4.2 ("One reading of the notice file") and v0.2 §6, written before the code.

An external review of 0.12.0, re-measured that day: `build_statement` (`cra attest`) read the notice file three times
(the bytes for the subject digests, the file again for the JSON, and `check_notice` again), so a file that changed
between two reads gave a SIGNED statement whose predicate described other bytes than the subject digest binds
(measured: `vulnerabilityIds` CVE-2024-9999 with the digest of a notice that carries CVE-2024-3094; `verify_envelope`
refused it with the drop, `vulnerability_ids`, and said `verified: true` without it). The verifier's `--drop` check
read the file three times too.

Every read of a file in this package goes through `ledger.open_regular`; the tests replace it so that the k-th opening
of the notice file sees other bytes (a changed CVE, a changed EUVD id, a changed stage, text that is not JSON, an
empty file), for every k up to one more than the number of readings 0.12.0 made. Rule: the answer is the one of a file
that held ONE content throughout — the original or the changed one — never a mixture; and the file is opened once.
Positive control: on 0.12.0 (4557a1f) these tests fail (measured 18/11/2026, see CHANGELOG 0.13.0)."""
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import ledger as L  # noqa: E402
from omega_cra_evol.art14_attest import AttestRefused, build_statement, verify_envelope  # noqa: E402

V2 = os.path.join(ROOT, "spec", "art14-filing", "v0.2", "vectors")
AT = datetime(2026, 11, 13, 7, 5, 0, tzinfo=timezone.utc)
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _mutations(raw: bytes):
    d = json.loads(raw)
    out = {}
    for name, path, value in (("cve", ("fields", "cve_id"), "CVE-2024-9999"),
                              ("euvd", ("fields", "euvd_id"), "EUVD-2024-99999"),
                              ("stage", ("stage",), "final_report")):
        x = copy.deepcopy(d)
        node = x
        for k in path[:-1]:
            node = node[k]
        if path[-1] in node:
            node[path[-1]] = value
            out[name] = json.dumps(x, indent=1).encode()
    out["not_json"] = b"{\"schema\": "
    out["empty"] = b""
    return out


class Swap:
    """ledger.open_regular, with the k-th opening of `target` reading `alt` instead; counts the openings of `target`"""

    def __init__(self, target, alt, k):
        self.target, self.alt, self.k, self.opens = os.path.realpath(target), alt, k, 0
        self.real = L.open_regular

    def __enter__(self):
        def hooked(path):
            if os.path.realpath(path) == self.target:
                self.opens += 1
                if self.opens == self.k:
                    return self.real(self.alt)
            return self.real(path)
        L.open_regular = hooked
        return self

    def __exit__(self, *a):
        L.open_regular = self.real


def _outcome(fn):
    try:
        return ("ok", fn())
    except (AttestRefused, ValueError, OSError) as e:
        return ("refused", type(e).__name__)


class ReadOnce(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.drop = os.path.join(self.td, "a", "drop_cve_euvd.json")
        os.makedirs(os.path.dirname(self.drop))
        shutil.copyfile(os.path.join(V2, "drop_cve_euvd.json"), self.drop)
        self.led = os.path.join(V2, "ledger.jsonl")
        with open(self.drop, "rb") as f:
            self.raw = f.read()
        self.muts = _mutations(self.raw)
        self.assertEqual(set(self.muts), {"cve", "euvd", "stage", "not_json", "empty"})

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def stable(self, content):
        """a file of the same name that holds `content` throughout"""
        d = tempfile.mkdtemp(dir=self.td)
        p = os.path.join(d, os.path.basename(self.drop))
        with open(p, "wb") as f:
            f.write(content)
        return p

    def build(self, drop):
        return build_statement(drop, self.led, attested_at=AT, predicate="v0.2")

    def test_attest_opens_the_notice_once(self):
        with Swap(self.drop, self.drop, 0) as s:
            self.build(self.drop)
        self.assertEqual(s.opens, 1)

    def test_attest_answer_is_one_content(self):
        clean = _outcome(lambda: self.build(self.drop))
        self.assertEqual(clean[0], "ok")
        self.assertIn(b"CVE-2024-3094", clean[1])                        # control: the notice's own identifier
        n = 0
        for name, content in self.muts.items():
            alt = self.stable(content)
            whole_alt = _outcome(lambda: self.build(alt))
            for k in range(1, 6):
                with Swap(self.drop, alt, k):
                    got = _outcome(lambda: self.build(self.drop))
                n += 1
                self.assertIn(got, (clean, whole_alt), (name, k, got))
                if got[0] == "ok":
                    self.assertNotIn(b"CVE-2024-9999", got[1], (name, k))
        self.assertEqual(n, 25)

    @unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` to verify the envelope before the drop is read")
    def test_verify_opens_the_notice_once_and_answers_for_one_content(self):
        from omega_cra_evol.ledger import load_trust_store
        with open(os.path.join(V2, "trust_store.json"), encoding="utf-8") as f:
            ts = load_trust_store(f.read())
        env = os.path.join(V2, "valid_cve_euvd_matched.intoto.json")
        clean = verify_envelope(env, ts, self.drop, self.led)
        self.assertTrue(clean["verified"], clean["reasons"])            # control
        with Swap(self.drop, self.drop, 0) as s:
            verify_envelope(env, ts, self.drop, self.led)
        self.assertEqual(s.opens, 1)
        for name, content in self.muts.items():
            alt = self.stable(content)
            whole_alt = verify_envelope(env, ts, alt, self.led)
            self.assertFalse(whole_alt["verified"], name)               # control: each change is seen when it holds
            for k in range(1, 6):
                with Swap(self.drop, alt, k):
                    got = verify_envelope(env, ts, self.drop, self.led)
                self.assertIn(json.dumps(got, sort_keys=True), (json.dumps(clean, sort_keys=True),
                                                               json.dumps(whole_alt, sort_keys=True)), (name, k))

    def test_nested_too_deep_is_a_refusal_not_a_traceback(self):
        """found while moving the parse onto the bytes (18/11/2026): a notice nested 200 000 deep raised RecursionError
        out of `build_statement` (a traceback in `cra attest`, which catches ValueError) and out of `verify_envelope`"""
        from omega_cra_evol.notice_check import check_notice, load_json_object
        deep = self.stable(b"[" * 200000 + b"]" * 200000)
        with self.assertRaises(ValueError):
            self.build(deep)
        with self.assertRaises(ValueError):
            load_json_object(deep)
        self.assertFalse(check_notice(deep, self.led)["verified"])
        if HAVE_CRYPTO:
            from omega_cra_evol.ledger import load_trust_store
            with open(os.path.join(V2, "trust_store.json"), encoding="utf-8") as f:
                ts = load_trust_store(f.read())
            r = verify_envelope(os.path.join(V2, "valid_cve_euvd_matched.intoto.json"), ts, deep, self.led)
            self.assertEqual([x["code"] for x in r["reasons"]][:1], ["drop_unreadable"])

    def test_bytes_given_keep_the_size_bound(self):
        """check_notice(raw=...) holds the bytes to the bound the file read holds them to (MAX_DROP_BYTES)"""
        from omega_cra_evol.notice_check import MAX_DROP_BYTES, check_notice
        ok = check_notice(self.drop, self.led, raw=self.raw)
        self.assertTrue(ok["verified"], ok["reasons"])                 # control: the same bytes, given
        padded = self.raw + b" " * (MAX_DROP_BYTES + 1 - len(self.raw))  # JSON that parses, one byte above the bound
        r = check_notice(self.drop, self.led, raw=padded)
        self.assertFalse(r["verified"])
        self.assertIn("FileTooLarge", r["reasons"][0])
        r = check_notice(self.drop, self.led, raw=padded[:-1])
        self.assertNotIn("FileTooLarge", " ".join(r["reasons"]))        # at the bound: read (and refused for its digest)

    def test_check_notice_opens_the_notice_once(self):
        from omega_cra_evol.notice_check import check_notice
        with Swap(self.drop, self.drop, 0) as s:
            r = check_notice(self.drop, self.led)
        self.assertTrue(r["verified"], r["reasons"])
        self.assertEqual(s.opens, 1)


if __name__ == "__main__":
    unittest.main()

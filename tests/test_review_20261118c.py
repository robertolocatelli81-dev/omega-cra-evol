# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 (review of the 0.13.0 branch): four defects measured on f7e9072, each test here fails there.

1. A generator document was opened with open(): `cra sbom`, `cra vex` and `cra vuln --vex` on a FIFO waited forever,
   on /dev/zero read until killed.
2. `record_vulnerability(components="left-pad")` recorded one query per character.
3. `notice_consistency` reported `@scope/pkg@2.0.0` as a component absent from the SBOM that holds `@scope/pkg`.
4. `cra verify-seal` without openssl said 74 ("not checked") for a seal whose sealer pin or algorithm policy fails."""
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_record_links_20261118 import Base, notice  # noqa: E402
from test_verify_seal_20261118 import HAVE_CRYPTO, HAVE_OPENSSL, LocalTsa, VerifySeal, cra  # noqa: E402

import _streams as ST  # noqa: E402
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(d, *args):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ROOT
    env["HOME"] = d
    return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", *args], cwd=d, capture_output=True, text=True,
                          env=env, timeout=20)


class NotRegularDocument(Base):
    def test_fifo_and_device_are_refused_unread(self):
        fifo = ST.fifo(self, self.td)                # Windows: a named pipe, and the NUL device
        base = ["--ledger", self.led, "--product", "p", "--version", "1"]
        for src in (fifo, ST.DEVICE):
            for args in (["sbom", *base, "--from-cyclonedx", src], ["sbom", *base, "--from-spdx", src],
                         ["vex", src, "--format", "openvex"],
                         ["vuln", *base, "--id", "CVE-2026-1", "--aware", "2026-11-18T09:00:00Z", "--vex", src,
                          "--vex-format", "openvex"]):
                r = run(self.td, *args)                     # on f7e9072: TimeoutExpired
                self.assertEqual(r.returncode, 2, (args, r.stdout, r.stderr))
                self.assertNotIn("Traceback", r.stderr)
                self.assertEqual(self.lines(), 0, args)

    def test_control_a_regular_file_is_still_read(self):
        p = os.path.join(self.td, "v.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"@context": "https://openvex.dev/ns/v0.3.0", "statements": []}, f)
        r = run(self.td, "vex", p, "--format", "openvex")
        self.assertEqual(r.returncode, 2)
        self.assertIn("only https://openvex.dev/ns/v0.2.0 is read", r.stderr)   # read, then refused for its content


class ComponentsArgument(Base):
    def test_a_bare_string_is_refused_and_nothing_written(self):
        lk = self.locker()
        n0 = self.lines()
        for bad in ("left-pad", b"left-pad", {"left-pad": 1}, 7):
            with self.assertRaises(ValueError):
                lk.record_vulnerability(self.rec(), components=bad)
            self.assertEqual(self.lines(), n0, bad)
        with self.assertRaises(ValueError):
            lk.match_components("left-pad")

    def test_control_list_and_tuple(self):
        lk = self.locker()
        for ok in (["left-pad"], ("left-pad",)):
            e = lk.record_vulnerability(self.rec(), components=ok)
            self.assertEqual([c["query"] for c in e["data"]["affected_components"]], ["left-pad"])


class ScopedNameInNotice(Base):
    def test_scoped_name_with_version(self):
        lk = self.locker()
        lk.record_vulnerability(self.rec())
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        for cn, found in (("@scope/pkg@2.0.0", True), ("@scope/pkg 2.0.0", True), ("@scope/pkg (2.0.0)", True),
                          ("@scope/pkg", True), ("left-pad@1.3.0", True), ("@scope/other@2.0.0", False),
                          ("@scope", False), ("scope/pkg", False)):
            r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", product_version="1", component_name=cn), now=now)
            self.assertEqual("component_not_in_sbom" not in [f["code"] for f in r["findings"]], found, cn)


@unittest.skipUnless(HAVE_CRYPTO and HAVE_OPENSSL, "a seal is signed and stamped: cryptography and openssl needed")
class VerifySealWithoutOpenssl(VerifySeal):
    locals().update({n: None for n in dir(VerifySeal) if n.startswith("test")})     # the parent's tests run in their file

    def test_a_failure_that_needs_no_openssl_is_1_not_74(self):
        tsa = LocalTsa(os.path.join(self.d, "tsa"))
        ps = self.pack()
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--print-imprint")
        tok = tsa.token(json.loads(r.stdout)["imprint_hex"])
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64", tok, "--tsa-cert", tsa.ca)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        empty = os.path.join(self.d, "emptybin")
        os.makedirs(empty)
        r, out = self.vs("--tsa-cert", tsa.ca, path=empty)                       # control: nothing fails, 74
        self.assertEqual(r.returncode, 74, r.stdout)
        r, out = self.vs("--tsa-cert", tsa.ca, "--sealer-pubkey", "0" * 64, path=empty)
        self.assertEqual(r.returncode, 1, r.stdout)                              # f7e9072: 74
        self.assertIn("not in trusted_pubs", " ".join(out["seals"][0]["verify"]["reasons"]))
        self.assertEqual(out["seals"][0]["verify"]["temporal_trust"], "not checked")
        r, out = self.vs("--tsa-cert", tsa.ca, "--at", "2036-06-01T00:00:00Z", path=empty)
        self.assertEqual(r.returncode, 1, r.stdout)                              # f7e9072: 74
        ps2 = self.pack("pack2.json")
        self.assertEqual(cra(self.d, "seal", *self.base, "--pack-sha3", ps2).returncode, 0)
        r, out = self.vs("--tsa-cert", tsa.ca, path=empty)                       # an asserted seal under --tsa-cert
        self.assertEqual(r.returncode, 1, r.stdout)                              # f7e9072: 74
        self.assertNotIn("failed_without_openssl", r.stdout)


    def test_a_valid_renewed_chain_without_openssl_is_74_not_1(self):
        """the note verify() adds to a renewal chain checked without an oracle is not a failure of the seal"""
        tsa = LocalTsa(os.path.join(self.d, "tsa"))
        ps = self.pack()
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--print-imprint")
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--ts-source", "rfc3161", "--token-b64",
                tsa.token(json.loads(r.stdout)["imprint_hex"]), "--tsa-cert", tsa.ca)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        prev = os.path.join(self.d, "prev.json")
        with open(prev, "w", encoding="utf-8") as f:
            json.dump(json.loads(r.stdout)["seal"], f)
        import time
        time.sleep(1.1)                                         # the renewal's genTime is later than the first record's
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--renew", prev, "--print-imprint")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--renew", prev, "--ts-source", "rfc3161", "--token-b64",
                tsa.token(json.loads(r.stdout)["imprint_hex"]), "--tsa-cert", tsa.ca)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r, out = self.vs("--tsa-cert", tsa.ca)                  # control, with openssl: the chain of two is verified
        self.assertEqual((r.returncode, out["seals"][0]["verify"]["chain_len"]), (0, 2), r.stdout)
        empty = os.path.join(self.d, "emptybin")
        os.makedirs(empty)
        r, out = self.vs("--tsa-cert", tsa.ca, path=empty)
        self.assertEqual(r.returncode, 74, r.stdout)            # the first patch: 1
        r, out = self.vs("--tsa-cert", tsa.ca, "--sealer-pubkey", "0" * 64, path=empty)
        self.assertEqual(r.returncode, 1, r.stdout)
        # the same chain renewed again WITHOUT a token: under --tsa-cert that record has nothing to verify, with or
        # without openssl (1, not 74)
        with open(self.led, encoding="utf-8") as f:
            last = [json.loads(ln)["data"] for ln in f if '"cra_longterm_seal"' in ln][-1]["lte"]
        with open(prev, "w", encoding="utf-8") as f:
            json.dump(last, f)
        r = cra(self.d, "seal", *self.base, "--pack-sha3", ps, "--renew", prev)
        self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
        r, out = self.vs("--tsa-cert", tsa.ca)
        self.assertEqual((r.returncode, out["seals"][0]["verify"]["chain_len"]), (1, 3), r.stdout)
        r, out = self.vs("--tsa-cert", tsa.ca, path=empty)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("no RFC 3161 token to verify under --tsa-cert", " ".join(out["seals"][0]["verify"]["reasons"]))


del VerifySeal       # its tests run in their own file


class EveryReaderIsARegularFileReader(Base):
    """the class of defect 1: a path given by the caller is read with ledger.read_regular everywhere"""

    def setUp(self):
        super().setUp()
        self.fifo = ST.fifo(self, self.td)          # Windows: a named pipe

    def test_api_readers(self):
        import threading
        from omega_cra_evol import kms, sbom as S, signing
        from omega_cra_evol.cli import _load_json
        from omega_cra_evol.ledger import Ledger
        from omega_cra_evol.time_anchor import _pins_pem
        calls = {"cli._load_json": lambda p: _load_json(p), "sbom.source_fingerprint": lambda p: S.source_fingerprint(p),
                 "kms.load_creds_file": lambda p: kms.load_creds_file(p), "signing.sign_pack": lambda p: signing.sign_pack(p, (None, ""), "s"),
                 "time_anchor._pins_pem": lambda p: _pins_pem([p])}
        if HAVE_CRYPTO:
            calls["signing.load_key"] = lambda p: signing.load_key(p)
        for name, fn in calls.items():
            for src in (self.fifo, ST.DEVICE):
                got = []
                def go():
                    try:
                        fn(src); got.append("returned")
                    except (OSError, ValueError) as e:
                        got.append(type(e).__name__)
                t = threading.Thread(target=go, daemon=True)
                t.start(); t.join(10)
                self.assertFalse(t.is_alive(), f"{name} blocks on {src}")
                self.assertNotEqual(got, ["returned"], (name, src))
        # the append-state cache next to a ledger: a FIFO in its place is "no cache", the append goes on
        if ST.WIN:
            self.skipTest("the readers above ran; the append-state part: " + ST.NO_FIFO)
        lg = Ledger(self.led)
        lg.append({"k": 1})
        state = self.led + ".append-state.json"
        if os.path.exists(state):
            os.remove(state)
        os.mkfifo(state)
        t = threading.Thread(target=lambda: Ledger(self.led).append({"k": 2}), daemon=True)
        t.start(); t.join(10)
        self.assertFalse(t.is_alive(), "Ledger.append blocks on a FIFO in place of its state cache")

    @unittest.skipIf(ST.WIN, ST.NO_FIFO)
    def test_a_fifo_in_place_of_a_stored_document(self):
        """the stores compare an existing file with the new bytes: a FIFO there is "different bytes", not a wait"""
        import hashlib
        import threading
        from omega_cra_evol import sbom as S, sbomify_import
        from omega_cra_evol.locker import source_file, sources_dir
        lk = self.locker(with_sbom=False)
        bom = os.path.join(self.td, "bom.json")
        with open(bom, "w", encoding="utf-8") as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "components": [{"type": "library", "name": "a", "version": "1", "bom-ref": "a"}]}, f)
        with open(bom, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        os.makedirs(sources_dir(self.led))
        os.mkfifo(source_file(self.led, sha))
        rec = S.sbom_from_cyclonedx(bom, "p", "1")
        for name, fn, want in (("record_sbom", lambda: lk.record_sbom(rec, source_path=bom), "already holds different bytes"),
                               ("sbomify _store", lambda: sbomify_import._store(self.fifo, b"x", []), "already holds different bytes")):
            got = []
            def go():
                try:
                    fn(); got.append("returned")
                except Exception as e:
                    got.append(str(e))
            t = threading.Thread(target=go, daemon=True)
            t.start(); t.join(10)
            self.assertFalse(t.is_alive(), f"{name} blocks on a FIFO in the store")
            self.assertIn(want, got[0], name)
        self.assertEqual(self.lines(), 0)

    def test_record_sbom_source_path_and_the_cli(self):
        import threading
        from omega_cra_evol import sbom as S
        lk = self.locker()                                      # records one SBOM from bom.json
        rec = S.sbom_from_cyclonedx(os.path.join(self.td, "bom.json"), "p", "1")
        n0, got = self.lines(), []
        def go():
            try:
                lk.record_sbom(rec, source_path=self.fifo); got.append("returned")
            except (OSError, ValueError) as e:
                got.append(str(e))
        t = threading.Thread(target=go, daemon=True)
        t.start(); t.join(10)
        self.assertFalse(t.is_alive(), "record_sbom blocks on a FIFO")
        self.assertIn("not a regular file", got[0])
        self.assertEqual(self.lines(), n0)
        base = ["--ledger", self.led, "--product", "p", "--version", "1"]
        for args in (["seal", *base, "--pack-sha3", "0" * 64, "--renew", self.fifo],
                     ["sign", os.path.join(self.td, "bom.json"), "--key", self.fifo, "--signer-id", "s"],
                     ["sign", self.fifo, "--key", self.fifo, "--signer-id", "s"],
                     ["verify-seal", "--ledger", self.led, "--tsa-cert", self.fifo]):
            r = run(self.td, *args)                             # before: TimeoutExpired on the first three
            self.assertNotEqual(r.returncode, 0, args)
            self.assertEqual(self.lines(), n0, args)


class ListsAreLists(Base):
    """the class of defect 2: an API that takes a list refuses a string or a dictionary"""

    def test_exploitation_signal(self):
        from omega_cra_evol import feeds
        kev = {"ids": {"CVE-2023-44487"}, "error": None, "count": 1}
        self.assertEqual(feeds.exploitation_signal(["CVE-2023-44487"], kev)["actively_exploited"], {"CVE-2023-44487": ["cisa_kev"]})
        for bad in ("CVE-2023-44487", {"CVE-2023-44487": 1}, None, 7):      # before: a string answered "not exploited"
            with self.assertRaises(ValueError):
                feeds.exploitation_signal(bad, kev)
        for bad in ("abc", {"name": "a"}, ["abc"], None):
            with self.assertRaises(ValueError):
                feeds.osv_query_batch(bad, timeout=1)

    def test_sbom_from_installed(self):
        from omega_cra_evol import sbom as S
        for bad in ("pip", {"pip": 1}, [1], [""], None, b"pip"):            # before: "pip" gave the components p and i
            with self.assertRaises(ValueError):
                S.sbom_from_installed("p", "1", bad)
        self.assertEqual(S.sbom_from_installed("p", "1", []).components, [])
        self.assertEqual([c.name for c in S.sbom_from_installed("p", "1", ["no-such-package-xyz"]).components], ["no-such-package-xyz"])

    def test_trusted_pubs(self):
        from omega_cra_evol.longterm import LongTermEvidence, Signer, register_algorithm
        register_algorithm("test-review", lambda: ("k", "ab" * 32), lambda sk, m: "00", lambda pub, sig, m: True)
        lte = LongTermEvidence("a" * 64)
        lte.seal(Signer("test-review"), 1.0)
        pub = lte.records[0]["pub"]
        for bad in ("ff" * 4 + pub + "00" * 4, pub, {pub: 1}, 7):           # before: a string holding the key passed
            with self.assertRaises(ValueError):
                lte.verify(now=2.0, trusted_pubs=bad)
        for ok in ({pub}, frozenset({pub}), [pub], (pub,)):
            self.assertNotIn("not in trusted_pubs", " ".join(lte.verify(now=2.0, trusted_pubs=ok)["reasons"]))
        self.assertIn("not in trusted_pubs", " ".join(lte.verify(now=2.0, trusted_pubs={"0" * 64})["reasons"]))

    def test_attachments(self):
        lk = self.locker(with_sbom=False)
        for bad in ("", "openvex", {}, {"format": "openvex", "document": {}}, 7):   # before: "" and {} meant "none"
            with self.assertRaises(ValueError):
                lk.record_vulnerability(self.rec(), attachments=bad)
        self.assertEqual(self.lines(), 0)
        lk.record_vulnerability(self.rec(), attachments=[])
        lk.record_vulnerability(self.rec(), attachments=None)
        self.assertEqual(self.lines(), 2)


if __name__ == "__main__":
    unittest.main()

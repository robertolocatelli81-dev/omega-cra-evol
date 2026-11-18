# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/RECORD_LINKS.md (written before the code): `cra vuln --component` links a vulnerability record to
a component of the recorded SBOM; `cra notice` prints what the notice says against what the ledger holds.

Measured with 0.12.0 on a ledger with a release SBOM and a vulnerability record: the affected component was nowhere,
and a notice naming another CVE, a component absent from the SBOM and a deadline already passed was recorded with exit
0 and no warning. The real SBOM used here: tests/data/real_release_sboms_20261118 (k9s v0.51.0, Apache-2.0).
Positive control: on c215a64 (before this code) this file fails (CHANGELOG 0.13.0)."""
import gzip
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import EvidenceLocker  # noqa: E402
from omega_cra_evol import sbom as S  # noqa: E402
from omega_cra_evol.srp_notice import SRPNotice, template  # noqa: E402
from omega_cra_evol.vuln import VulnerabilityRecord  # noqa: E402

REAL = os.path.join(ROOT, "tests", "data", "real_release_sboms_20261118")
try:
    import jsonschema  # noqa: F401
    HAVE_SCHEMA = True
except ImportError:
    HAVE_SCHEMA = False

COMPS = [("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"), ("@scope/pkg", "2.0.0", "pkg:npm/%40scope/pkg@2.0.0?arch=x#sub"),
         ("golang.org/x/net", "v0.15.0", "pkg:golang/golang.org/x/net@v0.15.0"), ("nopurl", "9", ""),
         ("left-pad", "1.1.0", "pkg:npm/left-pad@1.1.0")]


def cdx():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [dict({"type": "library", "name": n, "version": v, "bom-ref": f"r{i}"}, **({"purl": p} if p else {}))
                           for i, (n, v, p) in enumerate(COMPS)]}


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.led = os.path.join(self.td, "l.jsonl")

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def locker(self, with_sbom=True):
        lk = EvidenceLocker(self.led, "p", "1")
        if with_sbom:
            p = os.path.join(self.td, "bom.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(cdx(), f)
            lk.record_sbom(S.sbom_from_cyclonedx(p, "p", "1"), source_path=p)
        return lk

    def rec(self, vid="CVE-2023-44487", aware="2026-11-18T09:00:00Z"):
        return VulnerabilityRecord("p", vid, False, aware)

    def lines(self):
        if not os.path.exists(self.led):
            return 0
        with open(self.led, "rb") as f:
            return sum(1 for _ in f)


class Component(Base):
    def one(self, lk, q):
        return lk.match_components([q])["affected_components"][0]

    def test_queries(self):
        lk = self.locker()
        want = {"left-pad": 2, "left-pad@1.3.0": 1, "left-pad@1.1.0": 1, "left-pad@1.2.0": 0, "Left-Pad": 0, "left": 0,
                "@scope/pkg": 1, "@scope/pkg@2.0.0": 1, "@scope/pkg@2": 0, "nopurl": 1, "nopurl@9": 1,
                "golang.org/x/net@v0.15.0": 1, "golang.org/x/net@0.15.0": 0,
                "pkg:npm/left-pad": 2, "pkg:npm/left-pad@1.3.0": 1, "pkg:npm/left-pad@1.3.1": 0, "pkg:npm/left": 0,
                "pkg:npm/%40scope/pkg@2.0.0": 1, "pkg:npm/%40scope/pkg@2.0.0?arch=y": 1, "pkg:npm/%40scope/pkg": 1,
                "pkg:golang/golang.org/x/net@v0.15.0": 1, "pkg:pypi/left-pad@1.3.0": 0, "pkg:": 0}
        for q, n in want.items():
            r = self.one(lk, q)
            self.assertEqual((r["match_count"], r["in_sbom"]), (n, n > 0), q)
            self.assertEqual(len(r["matches"]), n, q)

    def test_generative_every_component_is_found_by_its_own_name_version_and_purl_and_no_mutation_is(self):
        lk = self.locker()
        rnd = random.Random(20261118)
        for n, v, p in COMPS:
            for q in (n, f"{n}@{v}") + ((p,) if p else ()):
                self.assertTrue(self.one(lk, q)["in_sbom"], q)
            for _ in range(30):
                q = rnd.choice([n, f"{n}@{v}", (p or n).split("?")[0].split("#")[0]])
                i = rnd.randrange(len(q))
                m = q[:i] + rnd.choice("zZ_~!") + q[i + 1:] if rnd.random() < .5 else q + rnd.choice("zZ0")
                if m == q:
                    continue
                r = self.one(lk, m)
                if m.startswith("pkg:"):     # the rule of spec/RECORD_LINKS.md §1, written again here
                    cut = [cp.split("?")[0].split("#")[0] for _, _, cp in COMPS if cp]
                    exact = m in cut or m in [c.split("@")[0] for c in cut]
                else:
                    exact = any(m in (cn, f"{cn}@{cv}") for cn, cv, _ in COMPS)
                self.assertEqual(r["in_sbom"], exact, (q, m))

    def test_refusals_record_nothing(self):
        lk = self.locker(with_sbom=False)
        with self.assertRaises(ValueError) as cm:
            lk.record_vulnerability(self.rec(), components=["left-pad"])
        self.assertIn("no SBOM recorded for p 1", str(cm.exception))
        self.assertEqual(self.lines(), 0)
        lk = self.locker()
        n = self.lines()
        for bad in ("", "   ", "x" * 1025, None, 1, ["a"]):
            with self.assertRaises(ValueError):
                lk.record_vulnerability(self.rec(), components=[bad])
        self.assertEqual(self.lines(), n)

    def test_the_sbom_of_another_version_is_not_this_product(self):
        self.locker()
        lk2 = EvidenceLocker(self.led, "p", "2")
        with self.assertRaises(ValueError):
            lk2.match_components(["left-pad"])
        lk3 = EvidenceLocker(self.led, "q", "1")
        with self.assertRaises(ValueError):
            lk3.match_components(["left-pad"])

    def test_the_record_carries_the_link_and_only_when_asked(self):
        lk = self.locker()
        e = lk.record_vulnerability(self.rec())
        self.assertNotIn("affected_components", e["data"])
        self.assertNotIn("sbom_record", e["data"])
        e = lk.record_vulnerability(self.rec(), components=["golang.org/x/net@v0.15.0", "log4j-core"])
        d = e["data"]
        self.assertEqual([(c["query"], c["in_sbom"]) for c in d["affected_components"]],
                         [("golang.org/x/net@v0.15.0", True), ("log4j-core", False)])
        self.assertEqual(d["affected_components"][0]["matches"],
                         [{"name": "golang.org/x/net", "version": "v0.15.0", "purl": "pkg:golang/golang.org/x/net@v0.15.0"}])
        first = next(lk.ledger.entries())
        self.assertEqual(d["sbom_record"], {"idx": first["idx"], "record_sha3": first["data"]["record_sha3"],
                                            "serial_number": first["data"]["sbom"]["serialNumber"],
                                            "source_sha256": first["data"]["source"]["sha256"]})
        self.assertTrue(lk.verify()["chain_ok"])

    def test_the_last_sbom_decides(self):
        lk = self.locker()
        d = cdx(); d["components"] = d["components"][:1]
        p = os.path.join(self.td, "bom2.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f)
        e2 = lk.record_sbom(S.sbom_from_cyclonedx(p, "p", "1"), source_path=p)
        r = lk.match_components(["nopurl", "left-pad"])
        self.assertEqual([c["in_sbom"] for c in r["affected_components"]], [False, True])
        self.assertEqual(r["sbom_record"]["idx"], e2["idx"])


def cra(td, *args):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["HOME"] = td
    return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli"] + list(args), capture_output=True, text=True, cwd=ROOT, env=env)


class VulnCli(Base):
    def vuln(self, *extra):
        return cra(self.td, "vuln", "--ledger", self.led, "--product", "p", "--version", "1", "--id", "CVE-2023-44487",
                   "--aware", "2026-11-18T09:00:00Z", *extra)

    def test_exit_codes(self):
        p = self.vuln("--component", "left-pad")
        self.assertEqual(p.returncode, 2, p.stderr)                      # no SBOM recorded
        self.assertIn("cra vuln: refused, nothing recorded: no SBOM recorded for p 1", p.stderr)
        self.assertEqual(self.lines(), 0)
        self.locker()
        n = self.lines()
        p = self.vuln("--component", "golang.org/x/net@v0.15.0", "--component", "pkg:npm/left-pad")
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual([c["match_count"] for c in out["affected_components"]], [1, 2])
        self.assertEqual(self.lines(), n + 1)
        p = self.vuln("--component", "log4j-core@2.14.1")
        self.assertEqual(p.returncode, 1, p.stderr)                      # recorded, not in the SBOM
        self.assertIn("cra vuln: warning: log4j-core@2.14.1 is not in the SBOM recorded at entry 0", p.stderr)
        self.assertFalse(json.loads(p.stdout)["affected_components"][0]["in_sbom"])
        self.assertEqual(self.lines(), n + 2)
        p = self.vuln("--component", "log4j-core@2.14.1", "--allow-not-in-sbom")
        self.assertEqual(p.returncode, 0, p.stderr)
        p = self.vuln("--component", "")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(self.lines(), n + 3)
        p = self.vuln()
        self.assertEqual(p.returncode, 0)
        self.assertNotIn("affected_components", json.loads(p.stdout))


def notice(aware, cve="CVE-2023-44487", **fields):
    f = template("vulnerability", "early_warning")
    f.update({"cve_id": cve, "awareness_datetime_utc": aware})
    f.update(fields)
    return SRPNotice(stream="vulnerability", stage="early_warning", fields=f)


class NoticeConsistency(Base):
    def codes(self, r):
        return [f["code"] for f in r["findings"]]

    def test_control_nothing_to_say(self):
        lk = self.locker()
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        lk.record_vulnerability(self.rec())
        r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", product_version="1", component_name="golang.org/x/net v0.15.0"), now=now)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["checked"], ["no_vulnerability_record", "deadline_passed", "product_version_differs", "component_not_in_sbom"])

    def test_the_measured_case(self):
        """the notice of 18/11: another CVE, a component absent from the SBOM, a deadline already passed"""
        lk = self.locker()
        lk.record_vulnerability(self.rec())
        n0 = self.lines()
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        r = lk.notice_consistency(notice("2026-11-10T09:00:00Z", cve="CVE-2021-44228", component_name="log4j-core 2.14.1",
                                         product_version="2"), now=now)
        self.assertEqual(self.codes(r), ["no_vulnerability_record", "deadline_passed", "product_version_differs", "component_not_in_sbom"])
        self.assertIn("CVE-2021-44228", r["findings"][0]["detail"])
        self.assertIn("due 2026-11-11T09:00:00+00:00", r["findings"][1]["detail"])
        self.assertEqual(self.lines(), n0)                    # nothing written

    def test_each_check_alone_and_only_when_its_inputs_exist(self):
        lk = self.locker(with_sbom=False)
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", cve="", component_name="x"), now=now)
        self.assertEqual((r["findings"], r["checked"]), ([], ["deadline_passed"]))        # no id, no SBOM, no product_version
        r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", cve="CVE-1"), now=now)
        self.assertEqual((self.codes(r), r["checked"]), (["no_vulnerability_record"], ["no_vulnerability_record", "deadline_passed"]))
        lk = self.locker()
        lk.record_vulnerability(self.rec("cve-2023-44487"))                               # ids compared without case
        r = lk.notice_consistency(notice("2026-11-18T09:00:00Z"), now=now)
        self.assertEqual(r["findings"], [])
        lk.record_vulnerability(self.rec("CVE-2024-3094"))
        r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", cve="cve-2024-3094"), now=now)   # … in either direction
        self.assertEqual(r["findings"], [])
        for name, found in (("left-pad", True), ("LEFT-PAD", True), ("left-pad@1.3.0", True), ("left-pad (1.3.0)", True),
                            ("the left-pad, version 1.3.0", True), ("leftpad", False), ("left", False), ("pad", False)):
            r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", component_name=name), now=now)
            self.assertEqual("component_not_in_sbom" not in self.codes(r), found, name)

    def test_deadline_boundary(self):
        lk = self.locker(with_sbom=False)
        due = datetime(2026, 11, 19, 9, 0, tzinfo=timezone.utc)
        for delta, passed in ((-1, False), (0, False), (1, True)):
            r = lk.notice_consistency(notice("2026-11-18T09:00:00Z", cve=""), now=due + timedelta(seconds=delta))
            self.assertEqual(self.codes(r) == ["deadline_passed"], passed, delta)


class NoticeCli(Base):
    def run_notice(self, fields, *extra):
        fp = os.path.join(self.td, "f.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(fields, f)
        return cra(self.td, "notice", "--ledger", self.led, "--product", "p", "--version", "1", "--stage", "early_warning",
                   "--fields", fp, "--drop", os.path.join(self.td, "drop"), *extra)

    def test_findings_are_printed_and_strict_decides_the_exit(self):
        lk = self.locker()
        lk.record_vulnerability(self.rec())
        f = template("vulnerability", "early_warning")
        f.update({"cve_id": "CVE-2021-44228", "awareness_datetime_utc": "2026-11-10T09:00:00Z", "component_name": "log4j-core 2.14.1"})
        p = self.run_notice(f)
        out = json.loads(p.stdout)
        codes = [x["code"] for x in out["ledger_consistency"]["findings"]]
        self.assertEqual(codes, ["no_vulnerability_record", "deadline_passed", "component_not_in_sbom"])
        self.assertEqual(sum(1 for ln in p.stderr.splitlines() if ln.startswith("cra notice: warning: ")), 3, p.stderr)
        self.assertEqual(p.returncode, 0 if out["complete"] else 1)          # as before: findings do not decide
        p = self.run_notice(f, "--strict")
        self.assertEqual(p.returncode, 1, p.stderr)
        # a COMPLETE notice: the findings alone decide, and only with --strict
        f.update({"notification_type": "Vulnerability", "title": "t", "summary": "s", "manufacturer_name": "m",
                  "member_states_available": ["IT"], "product_name": "p", "product_version": "1"})
        p = self.run_notice(f)
        out = json.loads(p.stdout)
        self.assertTrue(out["complete"], out)
        self.assertEqual((p.returncode, len(out["ledger_consistency"]["findings"])), (0, 3), p.stderr)
        p = self.run_notice(f, "--strict")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertTrue(json.loads(p.stdout)["complete"])
        # complete and nothing to say: --strict exits 0 (awareness one hour ago, the recorded id, a recorded component)
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        aware = (_dt.now(_tz.utc) - _td(hours=1)).isoformat(timespec="seconds")
        lk.record_vulnerability(VulnerabilityRecord("p", "CVE-2024-3094", False, aware))
        f.update({"cve_id": "CVE-2024-3094", "awareness_datetime_utc": aware, "component_name": "left-pad 1.3.0"})
        p = self.run_notice(f, "--strict")
        out = json.loads(p.stdout)
        self.assertEqual((p.returncode, out["ledger_consistency"]["findings"]), (0, []), p.stderr)
        self.assertNotIn("cra notice: warning", p.stderr)
        with open(self.led, encoding="utf-8") as fh:
            last = [json.loads(ln) for ln in fh][-1]["data"]
        self.assertEqual(last["kind"], "cra_srp_notice")
        self.assertNotIn("ledger_consistency", last)                         # the record's content does not change
        self.assertNotIn("ledger_consistency", last["drop"])


@unittest.skipUnless(HAVE_SCHEMA, "the real SBOM is recorded with its schema check (extra [schema])")
class RealSbom(Base):
    def test_k9s_component_found_in_the_release_sbom(self):
        with gzip.open(os.path.join(REAL, "k9s_v0.51.0_Darwin_amd64.tar.gz.sbom.json.gz"), "rb") as f:
            raw = f.read()
        p = os.path.join(self.td, "k9s.spdx.json")
        with open(p, "wb") as f:
            f.write(raw)
        lk = EvidenceLocker(self.led, "k9s", "v0.51.0")
        rec = S.sbom_from_spdx(p, "k9s", "v0.51.0")
        lk.record_sbom(rec, source_path=p)
        c = next(c for c in rec.components if c.purl.startswith("pkg:golang/") and c.version)
        e = lk.record_vulnerability(VulnerabilityRecord("k9s", "CVE-2023-44487", False, "2026-11-18T09:00:00Z"),
                                    components=[c.purl, f"{c.name}@{c.version}", "log4j-core"])
        self.assertEqual([x["in_sbom"] for x in e["data"]["affected_components"]], [True, True, False])
        self.assertEqual(e["data"]["sbom_record"]["source_sha256"], "4e8c27a168097842772b6b6be72a7d45b1ac67140fa672414f68ac8f5e2f93fa")


if __name__ == "__main__":
    unittest.main()

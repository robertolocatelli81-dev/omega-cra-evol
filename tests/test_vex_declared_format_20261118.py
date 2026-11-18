# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/VEX.md (written before the code): a document attached to a vulnerability record is checked for
the format its label declares; `cra vex`, `cra vuln --vex`.

Measured with 0.12.0 on 13 documents found on GitHub: 39 of 39 (document, label) pairs accepted, wrong labels and a file
that is not a VEX among them. Real documents: tests/data/real_vex_20261118 (MIT, CC0-1.0; SOURCES.txt); the others are
read from the network only when CRA_REAL_NET=1 (NETWORK.tsv: URL at a commit, sha256, verdict).
Positive control: on c215a64 (before this code) this file fails (CHANGELOG 0.13.0)."""
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import EvidenceLocker  # noqa: E402
from omega_cra_evol.vuln import VulnerabilityRecord  # noqa: E402

try:
    from omega_cra_evol import vex as V
except ImportError:                       # before 0.13.0: every test below fails on this
    V = None
REAL = os.path.join(ROOT, "tests", "data", "real_vex_20261118")
try:
    import jsonschema  # noqa: F401
    HAVE_SCHEMA = True
except ImportError:
    HAVE_SCHEMA = False
NEEDS_SCHEMA = unittest.skipUnless(HAVE_SCHEMA, "the schema check needs jsonschema (extra [schema])")
LABELS = ("openvex", "cyclonedx-vex", "cyclonedx-sbom", "csaf-2.0", "spdx-3.0")


def openvex():
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example.org/vex/1", "author": "Example PSIRT",
            "timestamp": "2026-11-18T10:00:00Z", "version": 1,
            "statements": [{"vulnerability": {"name": "CVE-2023-44487"}, "products": [{"@id": "pkg:golang/golang.org/x/net@v0.15.0"}],
                            "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}]}


def cdx_vex():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "vulnerabilities": [{"id": "CVE-2023-44487", "analysis": {"state": "not_affected"}}]}


def cdx_sbom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": "a", "version": "1.0.0", "bom-ref": "a"}]}


def csaf():
    return {"document": {"category": "csaf_vex", "csaf_version": "2.0", "title": "Example VEX",
                         "publisher": {"category": "vendor", "name": "Example", "namespace": "https://example.org"},
                         "tracking": {"id": "EX-1", "status": "final", "version": "1", "initial_release_date": "2026-11-18T10:00:00Z",
                                      "current_release_date": "2026-11-18T10:00:00Z",
                                      "revision_history": [{"date": "2026-11-18T10:00:00Z", "number": "1", "summary": "first"}]}}}


def spdx3():
    with open(os.path.join(ROOT, "tests", "fixtures", "spdx", "spdx-3.0-sbom.spdx3.json"), encoding="utf-8") as f:
        return json.load(f)


VALID = {"openvex": openvex, "cyclonedx-vex": cdx_vex, "cyclonedx-sbom": cdx_sbom, "csaf-2.0": csaf, "spdx-3.0": spdx3}


def refused(fmt, doc):
    try:
        V.check_attachment(fmt, doc)
    except ValueError as e:
        return str(e) or "(no reason)"
    return ""


class FormOnly(unittest.TestCase):
    """runs without jsonschema too: the label and the form decide before any schema"""

    def test_module_and_labels(self):
        self.assertIsNotNone(V, "omega_cra_evol.vex does not exist")
        self.assertEqual(set(V.ATTACHMENT_FORMATS), set(LABELS))

    def test_every_valid_document_is_refused_under_every_other_label(self):
        for label, make in VALID.items():
            for other in LABELS:
                if other == label or (label, other) == ("cyclonedx-vex", "cyclonedx-sbom"):   # a VEX BOM is a BOM
                    continue
                self.assertTrue(refused(other, make()), (label, "as", other))

    def test_unknown_label_and_not_an_object(self):
        for fmt in ("", "OpenVEX", "openvex ", "vex", "csaf-2.1", None, 1, ["openvex"]):
            self.assertIn("format must be one of", refused(fmt, openvex()), repr(fmt))
        for doc in (None, [], [openvex()], "x", 1, True):
            for label in LABELS:
                self.assertIn("not a JSON object", refused(label, doc), (label, doc))

    def test_openvex_context(self):
        for ctx in ("https://openvex.dev/ns", "https://openvex.dev/ns/v0.0.1", "https://openvex.dev/ns/v0.3.0",
                    "https://openvex.dev/ns/v0.2.0/", "http://openvex.dev/ns/v0.2.0", "", None, 1, ["https://openvex.dev/ns/v0.2.0"]):
            d = openvex(); d["@context"] = ctx
            self.assertTrue(refused("openvex", d), repr(ctx))
        d = openvex(); del d["@context"]
        self.assertIn("not an OpenVEX document", refused("openvex", d))
        d = openvex(); d["@context"] = "https://openvex.dev/ns/v0.0.1"
        self.assertIn("only https://openvex.dev/ns/v0.2.0 is read", refused("openvex", d))

    def test_csaf_form(self):
        self.assertEqual(V.check_attachment("csaf-2.0", csaf())["schema_check"], "form only (CSAF 2.0 schema not shipped)")
        for k in ("category", "csaf_version", "title", "publisher", "tracking"):
            d = csaf(); del d["document"][k]
            self.assertTrue(refused("csaf-2.0", d), k)
            for bad in (None, 1, [], ""):
                d = csaf(); d["document"][k] = bad
                self.assertTrue(refused("csaf-2.0", d), (k, bad))
        for ver in ("2.1", "1.2", 2.0, 2, "2"):
            d = csaf(); d["document"]["csaf_version"] = ver
            self.assertIn("csaf_version", refused("csaf-2.0", d), repr(ver))
        self.assertIn("`document`", refused("csaf-2.0", {"document": []}))

    def test_cyclonedx_vex_needs_vulnerabilities(self):
        for vulns in ([], None, {}, "x"):
            d = cdx_vex(); d["vulnerabilities"] = vulns
            self.assertTrue(refused("cyclonedx-vex", d), repr(vulns))
        d = cdx_vex(); del d["vulnerabilities"]
        self.assertIn("no vulnerabilities", refused("cyclonedx-vex", d))
        for bf in ("cyclonedx", "", None):
            d = cdx_vex(); d["bomFormat"] = bf
            self.assertIn("bomFormat", refused("cyclonedx-vex", d))

    def test_without_jsonschema_the_form_is_checked_and_the_schema_is_not(self):
        if HAVE_SCHEMA:
            self.skipTest("jsonschema is installed: the schema is checked (class Schema)")
        r = V.check_attachment("openvex", openvex())
        self.assertTrue(r["schema_check"].startswith("not checked: jsonschema is not installed"), r)
        r = V.check_attachment("cyclonedx-vex", cdx_vex())
        self.assertTrue(r["schema_check"].startswith("not checked: "), r)


@NEEDS_SCHEMA
class Schema(unittest.TestCase):
    def test_controls_are_accepted(self):
        want = {"openvex": "conformant to openvex_json_schema-0.2.0-93139bd.json", "cyclonedx-vex": "conformant to bom-1.6.schema.json",
                "cyclonedx-sbom": "conformant to bom-1.6.schema.json", "csaf-2.0": "form only (CSAF 2.0 schema not shipped)",
                "spdx-3.0": "conformant to spdx-json-schema-3.0.1.json"}
        for label, make in VALID.items():
            r = V.check_attachment(label, make())
            self.assertEqual((r["format"], r["schema_check"]), (label, want[label]))
        self.assertEqual(V.check_attachment("openvex", openvex())["statements"], 1)
        self.assertEqual(V.check_attachment("cyclonedx-vex", cdx_vex())["vulnerabilities"], 1)
        self.assertTrue(V.check_attachment("cyclonedx-sbom", cdx_vex())["schema_check"].startswith("conformant"))

    def test_openvex_generative(self):
        """a required member removed, a member of the wrong type, an unknown member at every level, statements emptied,
        a status outside the list: each refused, naming the schema"""
        rnd = random.Random(20261118)
        mutants = []
        for k in ("@id", "author", "timestamp", "version", "statements"):
            d = openvex(); del d[k]; mutants.append((f"-{k}", d))
        for k, bad in (("@id", 1), ("author", None), ("timestamp", 20261118), ("version", "one"), ("version", 0),
                       ("statements", {}), ("statements", [])):
            d = openvex(); d[k] = bad; mutants.append((f"{k}={bad!r}", d))
        for _ in range(40):
            d = openvex(); key = "x" + "".join(rnd.choice("abcdefghij_-0123") for _ in range(rnd.randint(1, 8)))
            where = rnd.choice(("top", "statement", "vulnerability", "product"))
            target = {"top": d, "statement": d["statements"][0], "vulnerability": d["statements"][0]["vulnerability"],
                      "product": d["statements"][0]["products"][0]}[where]
            target[key] = rnd.choice((1, "v", None, [], {}))
            mutants.append((f"+{where}.{key}", d))
        for st in ("fixed ", "Not_Affected", "unknown", "", None, 1):
            d = openvex(); d["statements"][0]["status"] = st; mutants.append((f"status={st!r}", d))
        d = openvex(); del d["statements"][0]["vulnerability"]["name"]; mutants.append(("-vulnerability.name", d))
        d = openvex(); d["statements"].append("not a statement"); mutants.append(("statement not an object", d))
        for name, d in mutants:
            why = refused("openvex", d)
            self.assertTrue(why.startswith("OpenVEX not conformant to openvex_json_schema-0.2.0-93139bd.json at ")
                            or why == "OpenVEX: statements is not an array", (name, why))

    def test_openvex_formats_are_reported_not_refused(self):
        d = openvex(); d["statements"][0]["products"][0]["@id"] = "pkg:deb/debian/libc6@>=0.0.0-0"     # '>' is not in an IRI
        r = V.check_attachment("openvex", d)
        self.assertEqual((r["schema_check"][:10], r["format_not_met"]), ("conformant", 1))
        self.assertIn("statements/0/products/0/@id", r["format_not_met_examples"][0])
        self.assertEqual(V.check_attachment("openvex", openvex())["format_not_met"], 0)

    def test_cyclonedx_is_checked_as_cra_sbom_checks_it(self):
        d = cdx_sbom(); d["components"][0]["type"] = "nonsense"
        self.assertIn("bom-1.6.schema.json", refused("cyclonedx-sbom", d))
        d = cdx_sbom(); d["components"].append(dict(d["components"][0], name="b"))
        self.assertIn("bom-ref unique", refused("cyclonedx-sbom", d))
        d = cdx_vex(); d["vulnerabilities"][0]["analysis"]["state"] = "maybe"
        self.assertIn("bom-1.6.schema.json", refused("cyclonedx-vex", d))
        d = cdx_vex(); d["specVersion"] = "9.9"
        self.assertTrue(refused("cyclonedx-vex", d))
        self.assertNotIn("--allow-nonconformant", refused("cyclonedx-vex", d))

    def test_spdx3(self):
        d = spdx3(); d["@graph"].append({"type": "no_such_type"})
        self.assertIn("spdx-json-schema-3.0.1.json", refused("spdx-3.0", d))
        d = spdx3(); d["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
        self.assertTrue(refused("spdx-3.0", d))


class Record(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.led = os.path.join(self.td, "l.jsonl")

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def rec(self):
        return VulnerabilityRecord("p", "CVE-2023-44487", False, "2026-11-18T09:00:00Z")

    def test_a_wrong_label_or_a_non_vex_records_nothing(self):
        lk = EvidenceLocker(self.led, "p", "1")
        with open(os.path.join(REAL, "openvex_spec_context.json"), encoding="utf-8") as f:
            context = json.load(f)
        cases = [(other, make()) for label, make in VALID.items() for other in LABELS
                 if other != label and (label, other) != ("cyclonedx-vex", "cyclonedx-sbom")]
        cases += [(label, context) for label in LABELS] + [("openvex", [])] + [("nope", openvex())]
        for label, doc in cases:
            with self.assertRaises(ValueError) as cm:
                lk.record_vulnerability(self.rec(), attachments=[{"format": label, "document": doc}])
            self.assertTrue(str(cm.exception).startswith("attachment 0"), str(cm.exception))
        for bad in ("x", None, ["openvex", {}]):
            with self.assertRaises(ValueError):
                lk.record_vulnerability(self.rec(), attachments=[bad])
        self.assertFalse(os.path.exists(self.led) and os.path.getsize(self.led))

    def test_second_attachment_refused_records_nothing(self):
        lk = EvidenceLocker(self.led, "p", "1")
        with self.assertRaises(ValueError) as cm:
            lk.record_vulnerability(self.rec(), attachments=[{"format": "csaf-2.0", "document": csaf()},
                                                             {"format": "csaf-2.0", "document": openvex()}])
        self.assertTrue(str(cm.exception).startswith("attachment 1 (csaf-2.0): "), str(cm.exception))
        self.assertFalse(os.path.exists(self.led) and os.path.getsize(self.led))

    def test_recorded_with_what_was_checked(self):
        lk = EvidenceLocker(self.led, "p", "1")
        e = lk.record_vulnerability(self.rec(), attachments=[{"format": "csaf-2.0", "document": csaf()},
                                                             {"format": "openvex", "document": openvex()}])
        a = e["data"]["attachments"]
        self.assertEqual(a[0]["schema_check"], "form only (CSAF 2.0 schema not shipped)")
        self.assertEqual(a[0]["document"], csaf())
        self.assertTrue(a[1]["schema_check"].startswith("conformant to openvex" if HAVE_SCHEMA else "not checked: "))
        self.assertTrue(lk.verify()["chain_ok"])


def cra(td, *args):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["HOME"] = td
    return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli"] + list(args), capture_output=True, text=True, cwd=ROOT, env=env)


class Cli(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def write(self, obj, name="v.json"):
        p = os.path.join(self.td, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))
        return p

    def test_cra_vex(self):
        p = cra(self.td, "vex", self.write(csaf()), "--format", "csaf-2.0")
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual((out["format"], out["schema_check"]), ("csaf-2.0", "form only (CSAF 2.0 schema not shipped)"))
        with open(self.write(csaf()), "rb") as f:
            self.assertEqual(out["sha256"], hashlib.sha256(f.read()).hexdigest())
        for label, content, want in (("openvex", csaf(), "not an OpenVEX document"), ("csaf-2.0", openvex(), "not a CSAF document"),
                                     ("openvex", '{"@context": 1, "@context": "https://openvex.dev/ns/v0.2.0"}', "duplicate"),
                                     ("openvex", "not json", "not JSON"), ("csaf-2.0", "[]", "not a JSON object")):
            p = cra(self.td, "vex", self.write(content), "--format", label)
            self.assertEqual((p.returncode, p.stdout), (2, ""), (label, p.stderr))
            self.assertEqual(len(p.stderr.splitlines()), 1, p.stderr)
            self.assertIn(want, p.stderr)
            self.assertTrue(p.stderr.startswith(f"cra vex: refused ({label}): "), p.stderr)
        p = cra(self.td, "vex", os.path.join(self.td, "absent.json"), "--format", "openvex")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        p = cra(self.td, "vex", self.write(csaf()), "--format", "nope")
        self.assertEqual(p.returncode, 2)

    def vuln(self, *extra):
        led = os.path.join(self.td, "l.jsonl")
        return led, cra(self.td, "vuln", "--ledger", led, "--product", "p", "--version", "1", "--id", "CVE-2023-44487",
                        "--aware", "2026-11-18T09:00:00Z", *extra)

    def test_cra_vuln_vex(self):
        led, p = self.vuln("--vex", self.write(openvex()), "--vex-format", "csaf-2.0")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("cra vuln: --vex refused (csaf-2.0), nothing recorded: ", p.stderr)
        self.assertEqual([x for x in os.listdir(self.td) if x.startswith("l.jsonl")], [])
        led, p = self.vuln("--vex", self.write(openvex()))
        self.assertEqual(p.returncode, 2)                    # usage: the two options go together
        self.assertEqual([x for x in os.listdir(self.td) if x.startswith("l.jsonl")], [])
        led, p = self.vuln("--vex", self.write(csaf()), "--vex-format", "csaf-2.0")
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["attachments"][0]["schema_check"], "form only (CSAF 2.0 schema not shipped)")
        with open(led, encoding="utf-8") as f:
            e = json.loads(f.readline())
        self.assertEqual(e["data"]["attachments"][0]["document"], csaf())


@NEEDS_SCHEMA
class RealVex(unittest.TestCase):
    def load(self, name, sha):
        with open(os.path.join(REAL, name), "rb") as f:
            raw = f.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
        return os.path.join(REAL, name)

    def test_fallow_is_an_openvex_document_and_nothing_else(self):
        p = self.load("fallow_openvex.json", "879dd69fe327ecbe5a306ed3532499f8493ce627febd6b000f97ea03bb40368b")
        r, _ = V.check_file(p, "openvex")
        self.assertEqual((r["schema_check"], r["statements"], r["format_not_met"]),
                         ("conformant to openvex_json_schema-0.2.0-93139bd.json", 1, 0))
        for other in ("cyclonedx-vex", "cyclonedx-sbom", "csaf-2.0", "spdx-3.0"):     # 0.12.0 kept it under each of them
            with self.assertRaises(ValueError):
                V.check_file(p, other)

    def test_asvs_empty_statements(self):
        p = self.load("asvs_bom.vex.json", "f06a24984004fcc5699a08e64b7b0c6fc4a2486ee81ec77dfa9f798b95d400af")
        with self.assertRaises(ValueError) as cm:
            V.check_file(p, "openvex")
        self.assertIn("not conformant to openvex_json_schema-0.2.0-93139bd.json", str(cm.exception))

    def test_the_jsonld_context_is_not_a_vex(self):
        p = self.load("openvex_spec_context.json", "e1a8917ca24b39134d3be498175fec5f42fdc0047d5d908ed2288dc06a693153")
        for label in LABELS:
            with self.assertRaises(ValueError):
                V.check_file(p, label)


@unittest.skipUnless(os.environ.get("CRA_REAL_NET") == "1" and HAVE_SCHEMA, "network test: CRA_REAL_NET=1")
class RealNetwork(unittest.TestCase):
    def test_each(self):
        with open(os.path.join(REAL, "NETWORK.tsv"), encoding="utf-8") as f:
            rows = [ln.rstrip("\n").split("\t") for ln in f if ln.strip() and not ln.startswith("#")]
        self.assertEqual(len(rows), 13)
        td = tempfile.mkdtemp()
        try:
            for url, sha, want in rows:
                with urllib.request.urlopen(url, timeout=120) as r:       # nosec B310 - fixed https URLs of this file
                    raw = r.read()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), sha, url)
                p = os.path.join(td, "v.json")
                with open(p, "wb") as f:
                    f.write(raw)
                try:
                    V.check_file(p, "openvex")
                    got = "accepted"
                except ValueError as e:
                    got = "refused: " + str(e)
                self.assertTrue(got.startswith(want), (url, got))
                for other in ("cyclonedx-vex", "cyclonedx-sbom", "csaf-2.0", "spdx-3.0"):
                    with self.assertRaises(ValueError):
                        V.check_file(p, other)
        finally:
            shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

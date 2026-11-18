# SPDX-License-Identifier: AGPL-3.0-or-later
"""spec/SBOM_INGEST.md 0.13.0: SPDX rules 6-7, CycloneDX rules 5-6.

Positive control: on 0.12.0 (3c15018) the SBOM that microsoft/sbom-tool v4.1.5 publishes for itself (SPDX 2.2, every
referenceCategory `PACKAGE-MANAGER`, as SPDX 2.2.2 §7.21 writes it) is refused; an SPDX 2.3 package with
`primaryPackagePurpose: OPERATING-SYSTEM` (§7.24) is refused; a seeAlsos value that is not a URL is recorded as
conformant; a repeated CycloneDX bom-ref (1.4-1.7) is recorded as conformant; an edge to a service is reported as dangling."""
import copy
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol.locker import EvidenceLocker  # noqa: E402
from omega_cra_evol.sbom import sbom_from_cyclonedx, sbom_from_spdx  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CTL = os.path.join(HERE, "data", "spdx_controls")
SUITE = os.path.join(HERE, "data", "cyclonedx_suite_6470e34")
SBOM_TOOL = os.path.join(HERE, "data", "sbom_tool_415", "linux-x64-manifest.spdx.json")
DATA = os.path.join(ROOT, "omega_cra_evol", "data", "spdx")

try:
    import jsonschema  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False
NEEDS = unittest.skipUnless(HAVE, "jsonschema not installed: the schema check cannot run here")

# The enum of spdx/spdx-spec PR #836 (development/v2.2.2, e3a5c7b) and of the tag v2.3.1, read 18/11/2026; written
# here, not taken from the vendored file, so a wrong vendored file fails this test.
CATEGORIES_SPDX = {"OTHER", "PERSISTENT-ID", "PERSISTENT_ID", "SECURITY", "PACKAGE-MANAGER", "PACKAGE_MANAGER"}


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def write(tmp, doc, name="d.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return p


def record(ingest, path, tmp, allow=False):
    rec = ingest(path, "p", "1", allow_nonconformant=allow)
    lk = EvidenceLocker(os.path.join(tmp, "l%d.jsonl" % random.randrange(10 ** 9)), "p", "1")
    return rec, lk.record_sbom(rec, source_path=path)


def accepted(ingest, path):
    try:
        return ingest(path, "p", "1").source["schema_check"].startswith("conformant to ")
    except ValueError:
        return False


@NEEDS
class TestSpdxSchemas(unittest.TestCase):
    def test_sbom_tool_document_is_conformant(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec, e = record(sbom_from_spdx, SBOM_TOOL, tmp)
        self.assertEqual(rec.source["schema_check"], "conformant to spdx-schema-v2.2.2-4694d1f.json")
        self.assertTrue(e["data"]["sbom_floor_met"])
        self.assertEqual(rec.source["packages_declared"], 235)

    def test_reference_categories(self):
        values = sorted(CATEGORIES_SPDX) + ["package-manager", "Package-Manager", "PACKAGE MANAGER", "PACKAGEMANAGER",
                                            "persistent-id", "Security", "other", "UNKNOWN", "", " SECURITY",
                                            "SECURITY\n", "PACKAGE‑MANAGER", "PACKAGE-MANAGER\x00", 1, None, [], {}]
        rnd = random.Random(20261118)
        values += ["".join(rnd.choice("PACKGE_-MNRSUITYO") for _ in range(rnd.randrange(1, 16))) for _ in range(40)]
        bases = (("tools-java_SPDXJSONExample-v2.2.spdx.json", "SPDX-2.2"), ("tools-java_SPDXJSONExample-v2.3.spdx.json", "SPDX-2.3"))
        seen = {True: 0, False: 0}
        with tempfile.TemporaryDirectory() as tmp:
            for base, ver in bases:
                d0 = load(os.path.join(CTL, base))
                self.assertEqual(d0["spdxVersion"], ver)
                pk = next(i for i, p in enumerate(d0["packages"]) if p.get("externalRefs"))
                for v in values:
                    d = copy.deepcopy(d0)
                    d["packages"][pk]["externalRefs"][0]["referenceCategory"] = v
                    want = isinstance(v, str) and v in CATEGORIES_SPDX
                    self.assertEqual(accepted(sbom_from_spdx, write(tmp, d)), want, (ver, v))
                    seen[want] += 1
        self.assertEqual(seen[True], 12)

    def test_operating_system_purpose_follows_the_23_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = load(os.path.join(CTL, "tools-java_SPDXJSONExample-v2.3.spdx.json"))
            for v, want in (("OPERATING-SYSTEM", True), ("OPERATING_SYSTEM", False), ("operating-system", False)):
                d["packages"][0]["primaryPackagePurpose"] = v
                self.assertEqual(accepted(sbom_from_spdx, write(tmp, d)), want, v)

    def test_23_dates_follow_the_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = load(os.path.join(CTL, "tools-java_SPDXJSONExample-v2.3.spdx.json"))
            for v, want in (("2020-01-01T00:00:00Z", True), ("2016-12-31T23:59:60Z", True), ("2020-01-01T00:00:00Z\n", False),
                            ("2020-01-01T00:00:00.5Z", False), ("2020-13-01T00:00:00Z", False), ("2020-01-01T00:00:00+01:00", False)):
                d["creationInfo"]["created"] = v
                self.assertEqual(accepted(sbom_from_spdx, write(tmp, d)), want, v)

    def test_23_requires_document_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = load(os.path.join(CTL, "tools-java_SPDXJSONExample-v2.3.spdx.json"))
            del d["documentNamespace"]
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(write(tmp, d), "p", "1")
            self.assertIn("not conformant to spdx-schema-v2.3.1.json", str(cm.exception))


@NEEDS
class TestSeeAlso(unittest.TestCase):
    def doc(self, values):
        d = load(os.path.join(CTL, "tools-java_SPDXJSONExample-v2.3.spdx.json"))
        d["hasExtractedLicensingInfos"][0]["seeAlsos"] = values
        return d

    def test_not_a_url_is_refused_and_a_local_url_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write(tmp, self.doc(["https://example.org/l.txt", "not a url"]))
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(p, "p", "1")
            self.assertIn("SPDX not conformant to SPDX-2.3 §10.4 at hasExtractedLicensingInfos/0/seeAlsos/1: "
                          "not a URL (RFC 3986 URI): 'not a url'", str(cm.exception))
            with self.assertRaises(ValueError) as cm:                   # the first one is named
                sbom_from_spdx(write(tmp, self.doc(["", "https://x/", "b c"]), "two.json"), "p", "1")
            self.assertIn("seeAlsos/0: not a URL (RFC 3986 URI): ''", str(cm.exception))
            rec, e = record(sbom_from_spdx, p, tmp, allow=True)
            self.assertTrue(rec.source["schema_check"].startswith("not conformant to SPDX-2.3 §10.4"))
            self.assertFalse(e["data"]["sbom_floor_met"])
            local = "file://$GOPATH/pkg/mod/github.com/github/go-spdx/v2@v2.7.0/cmd/licenses.json"
            rec, e = record(sbom_from_spdx, write(tmp, self.doc(["http://a.example/x", local, "ftp://h/x", "HTTPS://b/"])), tmp)
            self.assertEqual(rec.source["schema_check"], "conformant to spdx-schema-v2.3.1.json")
            self.assertTrue(e["data"]["sbom_floor_met"])
            self.assertEqual(rec.source["see_also_not_web"], 2)
            self.assertEqual(rec.source["see_also_not_web_examples"], [local, "ftp://h/x"])
            rec = sbom_from_spdx(write(tmp, self.doc(["https://example.org/l.txt"])), "p", "1")
            self.assertEqual(rec.source["see_also_not_web"], 0)
            long = "file:///" + "a" * 300
            rec = sbom_from_spdx(write(tmp, self.doc(["ftp://h/%d" % i for i in range(4)] + [long])), "p", "1")
            self.assertEqual(rec.source["see_also_not_web"], 5)
            self.assertEqual(rec.source["see_also_not_web_examples"], ["ftp://h/0", "ftp://h/1", "ftp://h/2"])
            rec = sbom_from_spdx(write(tmp, self.doc([long])), "p", "1")
            self.assertEqual(rec.source["see_also_not_web_examples"], [long[:200]])

    def test_the_schema_reason_comes_first(self):     # rule 7 runs only after the schema check passes
        with tempfile.TemporaryDirectory() as tmp:
            d = self.doc(["x y"])
            del d["documentNamespace"]
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(write(tmp, d), "p", "1")
            self.assertIn("not conformant to spdx-schema-v2.3.1.json", str(cm.exception))
            self.assertNotIn("§10.4", str(cm.exception))

    def test_the_22_document_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = load(os.path.join(CTL, "tools-java_SPDXJSONExample-v2.2.spdx.json"))
            d["hasExtractedLicensingInfos"][0]["seeAlsos"] = ["x y"]
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(write(tmp, d), "p", "1")
            self.assertIn("SPDX-2.2 §10.4", str(cm.exception))

    def test_generative_strings(self):
        uri = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9\-._~!$&'()*+,;=:@/?#%]*")   # an over-approximation
        ok = ["https://x", "urn:isbn:1", "file:///etc/l", "file://$GOPATH/a/b@v1/LICENSE", "mailto:a@b",
              "http://[::1]/", "http://h:8080/p?q=1#f", "a:", "x-y+z.1:%41",
              "http://h:/p", "http://h/p?a?b/c#d?e/f"]      # RFC 3986: empty port; "?" and "/" in query and fragment
        bad = ["", " ", "x", "//h/p", "/p", "1http://h", "http://h/p q", "http://h/è", "http://h/%4", "http://h/%zz",
               "http://h\n", "\thttp://h", "http://[::1/", "http://h/<x>", "http://h/\"", "http://h/{x}", "http://h/^",
               "http://h/`", "http://h/|", "http://h/\\",
               "a://:x", "a://h:x"]       # an authority whose port is not digits is no URI (no other hier-part fits)
        rnd = random.Random(1118)
        alphabet = "ah:/%$@[]#?. \t\nè-+1"
        gen = ["".join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 12))) for _ in range(150)]
        with tempfile.TemporaryDirectory() as tmp:
            for v in ok:
                self.assertTrue(accepted(sbom_from_spdx, write(tmp, self.doc([v]))), v)
            for v in bad:
                self.assertFalse(accepted(sbom_from_spdx, write(tmp, self.doc([v]))), v)
            for v in gen:       # never accepted when even the over-approximation refuses it
                if not uri.fullmatch(v):
                    self.assertFalse(accepted(sbom_from_spdx, write(tmp, self.doc([v]))), repr(v))


def cdx(spec="1.6", **extra):
    d = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
         "components": [{"type": "library", "bom-ref": "a", "name": "a", "version": "1"},
                        {"type": "library", "bom-ref": "b", "name": "b", "version": "1"}]}
    d.update(extra)
    return d


@NEEDS
class TestBomRefUnique(unittest.TestCase):
    def test_duplicates_anywhere_are_refused_from_14(self):
        placements = [
            lambda d: d["components"][1].update({"bom-ref": "a"}),
            lambda d: d["components"][0].update({"components": [{"type": "library", "bom-ref": "b", "name": "n", "version": "1"}]}),
            lambda d: d.update({"metadata": {"component": {"type": "application", "bom-ref": "a", "name": "m", "version": "1"}}}),
            lambda d: d.update({"services": [{"bom-ref": "b", "name": "s"}]}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for spec in ("1.2", "1.3", "1.4", "1.5", "1.6", "1.7"):
                self.assertTrue(accepted(sbom_from_cyclonedx, write(tmp, cdx(spec))), spec)
                self.assertEqual(sbom_from_cyclonedx(write(tmp, cdx(spec)), "p", "1").source["bom_ref_repeated"], 0)
                for i, put in enumerate(placements):
                    d = cdx(spec)
                    put(d)
                    p = write(tmp, d)
                    want = "a" if i in (0, 2) else "b"
                    if spec in ("1.2", "1.3"):       # JSON text "should be unique": reported, not refused
                        rec, e = record(sbom_from_cyclonedx, p, tmp)
                        self.assertEqual(rec.source["schema_check"], "conformant to bom-%s.schema.json" % spec)
                        self.assertEqual((rec.source["bom_ref_repeated"], rec.source["bom_ref_repeated_examples"]),
                                         (1, [want]), (spec, i))
                        self.assertTrue(e["data"]["sbom_floor_met"], (spec, i))
                        continue
                    with self.assertRaises(ValueError, msg=(spec, i)) as cm:
                        sbom_from_cyclonedx(p, "p", "1")
                    self.assertIn("not conformant to bom-%s (bom-ref unique within the BOM): " % spec, str(cm.exception))
                    self.assertIn("%r appears 2 times" % want, str(cm.exception))
                    rec, e = record(sbom_from_cyclonedx, p, tmp, allow=True)
                    self.assertFalse(e["data"]["sbom_floor_met"], (spec, i))
                    self.assertEqual((rec.source["bom_ref_repeated"], rec.source["bom_ref_repeated_examples"]),
                                     (1, [want]), (spec, i))

    def test_long_value_keeps_the_count(self):       # the value is cut at 120 so "appears <n> times" survives the 300 cut
        with tempfile.TemporaryDirectory() as tmp:
            d = cdx("1.6")
            d["components"][0]["bom-ref"] = d["components"][1]["bom-ref"] = "r" * 400
            with self.assertRaises(ValueError) as cm:
                sbom_from_cyclonedx(write(tmp, d), "p", "1")
            self.assertIn("'%s' appears 2 times" % ("r" * 120), str(cm.exception))

    def test_repeated_values_are_listed_in_document_order(self):
        refs = ["z", "z", "y" * 250, "y" * 250, "a", "a", "m", "m", "q"]
        with tempfile.TemporaryDirectory() as tmp:
            for spec in ("1.3", "1.6"):
                d = cdx(spec)
                d["components"] = [{"type": "library", "bom-ref": r, "name": "n%d" % i, "version": "1"}
                                   for i, r in enumerate(refs)]
                p = write(tmp, d)
                if spec == "1.6":
                    with self.assertRaises(ValueError) as cm:
                        sbom_from_cyclonedx(p, "p", "1")
                    self.assertIn("'z' appears 2 times", str(cm.exception))
                rec = sbom_from_cyclonedx(p, "p", "1", allow_nonconformant=True)
                self.assertEqual((rec.source["bom_ref_repeated"], rec.source["bom_ref_repeated_examples"]),
                                 (4, ["z", "y" * 200, "a"]), spec)

    def test_tool_component_repeated_as_annotator(self):     # cdxgen 12.8.4 writes this
        for f in ("cdxgen-12.8.4_cyclonedx-1.6.json", "cdxgen-12.8.4_cyclonedx-1.7.json"):
            with self.assertRaises(ValueError) as cm:
                sbom_from_cyclonedx(os.path.join(HERE, "fixtures", "real_tools", f), "p", "1")
            self.assertIn("'pkg:npm/@cyclonedx/cdxgen@12.8.4' appears 2 times", str(cm.exception))

    def test_exact_strings_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            for other in ("A", "a ", "а"):          # case, space, Cyrillic a: different strings, accepted
                d = cdx()
                d["components"][1]["bom-ref"] = other
                self.assertTrue(accepted(sbom_from_cyclonedx, write(tmp, d)), other)
            d = cdx("1.7")      # a patent assertion's bom-ref names the patent (1.7 JSON text): not a second identifier
            d["definitions"] = {"patents": [{"bom-ref": "pat-1", "patentNumber": "US1", "jurisdiction": "US",
                                             "patentLegalStatus": "in-force"}]}
            d["components"][0]["patentAssertions"] = [{"bom-ref": "pat-1", "assertionType": "ownership",
                                                       "asserter": {"email": "a@example.org"}}]
            self.assertTrue(accepted(sbom_from_cyclonedx, write(tmp, d)))

    def test_official_suite_json_files_whose_xml_twin_is_unique(self):
        for v, name in (("1.5", "valid-formulation-1.5.json"), ("1.7", "valid-citations-1.7.json")):
            with self.assertRaises(ValueError) as cm:
                sbom_from_cyclonedx(os.path.join(SUITE, v, name), "p", "1")
            self.assertIn("bom-ref unique within the BOM", str(cm.exception))

    def test_generative(self):
        rnd = random.Random(181118)
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(80):
                spec = rnd.choice(("1.2", "1.3", "1.4", "1.5", "1.6", "1.7"))
                pool = ["r%d" % rnd.randrange(6) for _ in range(rnd.randrange(1, 7))]
                comps = [{"type": "library", "bom-ref": r, "name": "n%d" % j, "version": "1"} for j, r in enumerate(pool)]
                nest = rnd.randrange(len(comps))
                if len(comps) > 1 and nest:
                    comps[0]["components"] = [comps.pop(nest)]
                d = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1, "components": comps}
                want = len(set(pool)) == len(pool) or spec in ("1.2", "1.3")
                p = write(tmp, d)
                self.assertEqual(accepted(sbom_from_cyclonedx, p), want, (i, spec, pool))
                rec = sbom_from_cyclonedx(p, "p", "1", allow_nonconformant=True)
                self.assertEqual(rec.source["bom_ref_repeated"], sum(1 for r in set(pool) if pool.count(r) > 1), (i, pool))


@NEEDS
class TestReferences(unittest.TestCase):
    def test_edges_to_services_resolve_and_fields_are_counted(self):
        d = cdx("1.6", services=[{"bom-ref": "svc", "name": "s"}],
                dependencies=[{"ref": "a", "dependsOn": ["svc", "b", "ghost"]}, {"ref": "nobody", "provides": ["gone"]},
                              {"ref": "b", "dependsOn": ["urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#x"]}],
                vulnerabilities=[{"bom-ref": "v1", "id": "CVE-2026-0001"}],
                compositions=[{"aggregate": "complete", "assemblies": ["a", "lost"], "dependencies": ["b"],
                               "vulnerabilities": ["v1", "v9"]}])
        with tempfile.TemporaryDirectory() as tmp:
            rec, _ = record(sbom_from_cyclonedx, write(tmp, d), tmp)
        s = rec.source
        self.assertEqual(s["dangling_edges"], 1)
        self.assertEqual(s["dangling_refs"], ["ghost", "gone", "lost", "nobody", "v9"])
        self.assertEqual(s["dangling_by_field"], {"compositions.assemblies": 1, "compositions.vulnerabilities": 1,
                                                  "dependencies.dependsOn": 1, "dependencies.provides": 1,
                                                  "dependencies.ref": 1})
        d3 = cdx("1.6", dependencies=[{"ref": "a", "dependsOn": ["x%02d" % i for i in range(12)]}])
        with tempfile.TemporaryDirectory() as tmp:
            s3 = sbom_from_cyclonedx(write(tmp, d3), "p", "1").source
        self.assertEqual((s3["dangling_edges"], s3["dangling_refs"]), (12, ["x%02d" % i for i in range(10)]))
        d2 = cdx("1.6", dependencies=[{"ref": "a", "dependsOn": ["b"]}])
        with tempfile.TemporaryDirectory() as tmp:
            s2 = sbom_from_cyclonedx(write(tmp, d2), "p", "1").source
        self.assertEqual((s2["dangling_edges"], s2["dangling_refs"], s2["dangling_by_field"]), (0, [], {}))


@NEEDS
class TestCli(unittest.TestCase):
    def test_sbom_tool_document_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            env["HOME"] = tmp
            p = subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", "sbom", "--ledger", os.path.join(tmp, "l.jsonl"),
                                "--product", "sbom-tool", "--version", "4.1.5", "--from-spdx", SBOM_TOOL],
                               capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["source"]["schema_check"], "conformant to spdx-schema-v2.2.2-4694d1f.json")


if __name__ == "__main__":
    unittest.main()

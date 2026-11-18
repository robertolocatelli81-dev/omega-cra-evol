# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 (evening) — spec/SBOM_INGEST.md, amendment written before the code: SPDX rule 8 (SPDXID unique,
refused), SPDX rule 9 (text rules reported with their section), rule 10 (an SBOM inside an in-toto Statement), rule 11
(Syft JSON refused by name), the floor without ranges and CI actions, the BSI TR-03183-2 notice.

Real documents: three release SBOMs kept in tests/data/real_release_sboms_20261118 (MIT / Apache-2.0, SOURCES.txt);
the other measured documents (AGPL, GPL, MPL, EUPL licences, or not reproducible) are read from the network only when
CRA_REAL_NET=1, by URL and sha256 (tests/data/real_release_sboms_20261118/NETWORK.tsv).
Positive control: on c215a64 (before this code) this file fails (measured, CHANGELOG 0.13.0)."""
import copy
import gzip
import hashlib
import json
import os
import random
import re
import shutil
import string
import sys
import tempfile
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import sbom as S  # noqa: E402

REAL = os.path.join(ROOT, "tests", "data", "real_release_sboms_20261118")
try:
    import jsonschema  # noqa: F401
    HAVE_SCHEMA = True
except ImportError:
    HAVE_SCHEMA = False
NEEDS_SCHEMA = unittest.skipUnless(HAVE_SCHEMA, "the schema check needs jsonschema (extra [schema])")


def spdx23(packages=2, files=0, describes=True, **extra):
    d = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "doc",
         "documentNamespace": "https://example.org/spdx/doc-1",
         "creationInfo": {"created": "2026-11-18T10:00:00Z", "creators": ["Tool: test-1.0"]},
         "packages": [{"SPDXID": f"SPDXRef-P{i}", "name": f"p{i}", "versionInfo": f"1.{i}.0",
                       "downloadLocation": "NOASSERTION"} for i in range(packages)],
         "relationships": []}
    if describes and packages:
        d["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                   "relatedSpdxElement": "SPDXRef-P0"})
    if files:
        d["files"] = [{"SPDXID": f"SPDXRef-F{i}", "fileName": f"./src/f{i}.c",
                       "checksums": [{"algorithm": "SHA1", "checksumValue": "a" * 40}],
                       "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION"} for i in range(files)]
    d.update(extra)
    return d


def to22(d):
    """the 2.2 schema SPDX corrected also requires a package's licences and copyright text"""
    d["spdxVersion"] = "SPDX-2.2"
    for p in d["packages"]:
        p.update({"licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"})
    return d


def cdx16(**extra):
    d = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
         "components": [{"type": "library", "name": "a", "version": "1.0.0", "bom-ref": "a"},
                        {"type": "library", "name": "b", "version": "2.0.0", "bom-ref": "b"}]}
    d.update(extra)
    return d


class Docs(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def write(self, obj, name="d.json"):
        p = os.path.join(self.td, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))
        return p

    def spdx(self, obj, allow=False):
        return S.sbom_from_spdx(self.write(obj), "p", "1", allow_nonconformant=allow)

    def cdx(self, obj, allow=False):
        return S.sbom_from_cyclonedx(self.write(obj), "p", "1", allow_nonconformant=allow)


@NEEDS_SCHEMA
class SpdxIdUnique(Docs):
    """SPDX rule 8: SPDX 2.3 §6.3/§7.2/§8.2/§9.1 "a unique string" -> refused (0.12.0: accepted)"""

    def test_control_unique_is_accepted(self):
        r = self.spdx(spdx23(packages=3, files=2))
        self.assertTrue(r.source["schema_check"].startswith("conformant to "), r.source)
        self.assertEqual(r.source["spdxid_repeated"], 0)

    def test_generative_repeats_anywhere(self):
        rnd = random.Random(20261118)
        n = 0
        for _ in range(60):
            d = spdx23(packages=rnd.randint(2, 5), files=rnd.randint(0, 3))
            slots = [("doc", None)] + [("packages", i) for i in range(len(d["packages"]))] + \
                    [("files", i) for i in range(len(d.get("files", [])))]
            a, b = rnd.sample(slots, 2)
            src = d["SPDXID"] if a[0] == "doc" else d[a[0]][a[1]]["SPDXID"]
            if b[0] == "doc":
                d["SPDXID"] = src
            else:
                d[b[0]][b[1]]["SPDXID"] = src
            if d["SPDXID"] != "SPDXRef-DOCUMENT":
                continue                                    # the 2.3.1 schema requires SPDXRef-DOCUMENT itself
            n += 1
            with self.assertRaises(ValueError) as cm:
                self.spdx(d)
            self.assertIn("§7.2 (SPDXID unique)", str(cm.exception))
            self.assertIn(repr(src), str(cm.exception))
            r = self.spdx(d, allow=True)                    # --allow-nonconformant: recorded, never conformant
            self.assertTrue(r.source["schema_check"].startswith("not conformant to SPDX-2.3 §7.2"), r.source)
            self.assertEqual(r.source["spdxid_repeated"], 1)
            self.assertEqual(r.source["spdxid_repeated_examples"], [src])
        self.assertGreater(n, 20)

    def test_three_times_is_counted(self):
        d = spdx23(packages=4)
        for p in d["packages"][1:]:
            p["SPDXID"] = "SPDXRef-P0"
        with self.assertRaises(ValueError) as cm:
            self.spdx(d)
        self.assertIn("appears 4 times", str(cm.exception))

    def test_spdx22_too(self):
        d = to22(spdx23(packages=2))
        d["packages"][1]["SPDXID"] = "SPDXRef-P0"
        with self.assertRaises(ValueError) as cm:
            self.spdx(d)
        self.assertIn("SPDX-2.2 §7.2 (SPDXID unique)", str(cm.exception))


@NEEDS_SCHEMA
class SpdxTextRules(Docs):
    """SPDX rule 9: reported in source.spec_rules with the section, never a refusal"""

    def rules(self, d):
        return {r["section"]: r for r in self.spdx(d).source["spec_rules"]}

    def test_control_clean_document(self):
        self.assertEqual(self.rules(spdx23(packages=3, files=2)), {})

    def test_absolute_file_name(self):
        for name, bad in (("/tmp/x", True), ("\\x", True), ("C:\\x", True), ("c:/x", True), ("./a/b", False),
                          ("a/b", False), ("./C:/x", False), ("..", False)):
            d = spdx23(files=1)
            d["files"][0]["fileName"] = name
            got = self.rules(d)
            self.assertEqual("SPDX-2.3 §8.1" in got, bad, name)
            if bad:
                self.assertEqual(got["SPDX-2.3 §8.1"]["examples"], [name])

    def test_file_without_sha1(self):
        for algs, bad in ((["SHA256"], True), (["SHA1"], False), (["SHA256", "SHA1"], False), (["sha1"], True)):
            d = spdx23(files=1)
            d["files"][0]["checksums"] = [{"algorithm": a, "checksumValue": "b" * (40 if "1" in a else 64)} for a in algs]
            try:
                got = self.rules(d)
            except ValueError:                          # a lower-case algorithm is outside the schema's enum
                self.assertEqual(algs, ["sha1"])
                continue
            self.assertEqual("SPDX-2.3 §8.4" in got, bad, algs)

    def test_describes(self):
        self.assertIn("SPDX-2.3 §11.1", self.rules(spdx23(packages=2, describes=False)))
        self.assertNotIn("SPDX-2.3 §11.1", self.rules(spdx23(packages=1, describes=False)))   # one package: not mandatory
        d = spdx23(packages=2, describes=False, documentDescribes=["SPDXRef-P0"])               # the JSON field: present
        self.assertNotIn("SPDX-2.3 §11.1", self.rules(d))
        d = spdx23(packages=2, describes=False)
        d["relationships"].append({"spdxElementId": "SPDXRef-P1", "relationshipType": "DESCRIBED_BY",
                                   "relatedSpdxElement": "SPDXRef-DOCUMENT"})
        self.assertNotIn("SPDX-2.3 §11.1", self.rules(d))
        d = spdx23(packages=2, describes=False)
        d["relationships"].append({"spdxElementId": "SPDXRef-P0", "relationshipType": "DESCRIBES",
                                   "relatedSpdxElement": "SPDXRef-P1"})                 # not the document: not one
        self.assertIn("SPDX-2.3 §11.1", self.rules(d))

    def test_spdx22_idstring(self):
        d = to22(spdx23(packages=2))
        d["packages"][1]["SPDXID"] = "SPDXRef-a+b"
        d["relationships"] = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": "SPDXRef-P0"}]
        got = self.rules(d)
        self.assertEqual(got["SPDX-2.2 §6.3/§7.2/§8.2/§9.1"]["examples"], ["SPDXRef-a+b"])
        d["spdxVersion"] = "SPDX-2.3"                       # 2.3: the 2.3.1 schema refuses it (pattern)
        with self.assertRaises(ValueError):
            self.spdx(d)

    def test_conformant_names_the_schema_only(self):
        r = self.spdx(spdx23(packages=2, describes=False))
        self.assertRegex(r.source["schema_check"], r"^conformant to spdx-schema-v2\.3\.1\.json$")
        self.assertTrue(r.source["spec_rules"])


@NEEDS_SCHEMA
class InToto(Docs):
    """rule 10: the predicate of an in-toto Statement with a CycloneDX/SPDX predicate type is the document"""

    def stmt(self, pred, pt="https://spdx.dev/Document", t="https://in-toto.io/Statement/v1"):
        return {"_type": t, "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}], "predicateType": pt,
                "predicate": pred}

    def test_spdx_and_cyclonedx_statements(self):
        for pt in ("https://spdx.dev/Document", "https://spdx.dev/Document/v2.3"):
            for t in ("https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"):
                r = self.spdx(self.stmt(spdx23(), pt, t))
                self.assertEqual((r.source["wrapper"], r.source["wrapper_predicate_type"], r.source["wrapper_subjects"]),
                                 ("in-toto-statement", pt, 1))
                self.assertTrue(r.source["schema_check"].startswith("conformant to "))
        for pt in ("https://cyclonedx.org/bom", "https://cyclonedx.org/bom/v1.6"):
            r = self.cdx(self.stmt(cdx16(), pt))
            self.assertEqual(r.source["wrapper"], "in-toto-statement")
        p = self.write(self.stmt(spdx23()))
        with open(p, "rb") as f:
            self.assertEqual(S.sbom_from_spdx(p, "p", "1").source["sha256"], hashlib.sha256(f.read()).hexdigest())

    def test_the_predicate_is_checked_like_a_document(self):
        bad = spdx23()
        bad["packages"][1]["SPDXID"] = "SPDXRef-P0"
        with self.assertRaises(ValueError):
            self.spdx(self.stmt(bad))
        c = cdx16()
        c["components"][1]["bom-ref"] = "a"
        with self.assertRaises(ValueError):
            self.cdx(self.stmt(c, "https://cyclonedx.org/bom"))

    def test_refusals_by_name(self):
        cases = [
            (self.stmt(spdx23(), "https://slsa.dev/provenance/v1"), "predicateType"),
            (self.stmt(spdx23(), "https://spdx.dev/DocumentX"), "predicateType"),
            (self.stmt(spdx23(), "https://spdx.dev/Document/v2.3 "), "predicateType"),
            (self.stmt(spdx23(), 7), "predicateType"),
            (self.stmt(spdx23(), t="https://in-toto.io/Statement/v2"), "_type"),
            (self.stmt(spdx23(), t=None), "_type"),
            (self.stmt([spdx23()]), "predicate is not a JSON object"),
            (self.stmt(cdx16(), "https://cyclonedx.org/bom"), "--from-cyclonedx"),
            ({"payloadType": "application/vnd.in-toto+json", "payload": "e30=", "signatures": []}, "DSSE"),
            ({"predicateType": "https://spdx.dev/Document", "predicate": spdx23()}, "_type"),
        ]
        for doc, why in cases:
            with self.assertRaises(ValueError, msg=why) as cm:
                self.spdx(doc)
            self.assertIn(why, str(cm.exception))

    def test_generative_type_strings(self):
        rnd = random.Random(7)
        good_pt = {"https://spdx.dev/Document", "https://spdx.dev/Document/v2.3", "https://spdx.dev/Document/v3"}
        for _ in range(200):
            base = rnd.choice(sorted(good_pt))
            op = rnd.randrange(4)
            pt = (base + rnd.choice(string.printable) if op == 0 else base[:-1] if op == 1 else
                  base.upper() if op == 2 else base.replace("https", "http"))
            if re.fullmatch(r"https://spdx\.dev/Document(/v[0-9]+(\.[0-9]+)*)?", pt):
                continue                                # the spec's grammar: a version after /v is one
            with self.assertRaises(ValueError):
                self.spdx(self.stmt(spdx23(), pt))


class SyftJson(Docs):
    def test_refused_by_name(self):
        d = {"artifacts": [], "artifactRelationships": [], "source": {}, "distro": {},
             "descriptor": {"name": "syft", "version": "1.57.2"}, "schema": {}}
        for fn in (self.spdx, self.cdx):
            with self.assertRaises(ValueError) as cm:
                fn(d)
            self.assertIn("syft convert", str(cm.exception))


class Floor(unittest.TestCase):
    def test_ranges_and_ci(self):
        for v, rng in ((">= 2.5,< 4", True), ("^1.2.3", True), ("~1.2", True), ("1.*", True), ("1.0 - 2.0", True),
                       ("<3", True), ("=1.0", True), ("1.0||2.0", True), ("5.7-0.5~deb12u1", False), ("1.0+build", False),
                       ("1:2.3-4", False), ("v1.2.3", False), ("2026.11.18", False), ("1.0.0-rc.1", False)):
            self.assertEqual(S.is_version_range(v), rng, v)
        rec = S.SBOMRecord("p", "1", [S.SBOMComponent("a", ">= 1.0"), S.SBOMComponent("b", "1.0"),
                                      S.SBOMComponent("actions/checkout", "v4", purl="pkg:githubactions/actions/checkout@v4"),
                                      S.SBOMComponent("c", "~deb")])
        self.assertEqual([c.name for c in S.resolved_components(rec)], ["b"])

    def test_generative_versions_without_range_characters_are_versions(self):
        rnd = random.Random(3)
        alphabet = string.ascii_letters + string.digits + ".-+:~_"
        for _ in range(2000):
            v = rnd.choice(string.digits) + "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 12)))
            self.assertFalse(S.is_version_range(v), v)
            self.assertTrue(S.is_version_range(v + rnd.choice("<>=,|^* ")), v)


@NEEDS_SCHEMA
class BsiNotice(Docs):
    def test_format_minimum(self):
        for spec, met in (("1.4", False), ("1.5", False), ("1.6", True), ("1.7", True)):
            r = self.cdx(cdx16(specVersion=spec))
            n = r.source["bsi_tr_03183_2"]
            self.assertEqual((n["version"], n["format_minimum_met"]), ("2.1.0", met), spec)
        r = self.spdx(spdx23())
        self.assertFalse(r.source["bsi_tr_03183_2"]["format_minimum_met"])


@NEEDS_SCHEMA
class RealReleaseSboms(Docs):
    """three release SBOMs (MIT / Apache-2.0), unmodified: what 0.12.0 missed on each"""

    def load(self, name, sha):
        with gzip.open(os.path.join(REAL, name), "rb") as f:
            raw = f.read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
        p = os.path.join(self.td, name[:-3])
        with open(p, "wb") as f:
            f.write(raw)
        return p

    def test_codebase_memory_mcp_describes(self):
        p = self.load("codebase-memory-mcp_v0.12.1_sbom.json.gz", "5cd10369a2fa1414475357c5b8ef60c269b920d2122635e968e3591ddc19d909")
        r = S.sbom_from_spdx(p, "p", "1")
        self.assertEqual([x["section"] for x in r.source["spec_rules"]], ["SPDX-2.3 §11.1"])

    def test_k9s_file_rules(self):
        p = self.load("k9s_v0.51.0_Darwin_amd64.tar.gz.sbom.json.gz", "4e8c27a168097842772b6b6be72a7d45b1ac67140fa672414f68ac8f5e2f93fa")
        rules = {x["section"]: x for x in S.sbom_from_spdx(p, "p", "1").source["spec_rules"]}
        self.assertEqual(sorted(rules), ["SPDX-2.3 §8.1", "SPDX-2.3 §8.4"])
        self.assertEqual(rules["SPDX-2.3 §8.1"]["count"], 1)
        self.assertTrue(rules["SPDX-2.3 §8.1"]["examples"][0].startswith("/private/var/folders/"))
        self.assertEqual(rules["SPDX-2.3 §8.4"]["count"], 3)

    def test_docker_compose_in_toto(self):
        p = self.load("docker-compose_v5.8.0_darwin-aarch64.sbom.json.gz", "3ed77f6d576a9f4986e395bb121f294b6359e7727320c89caee6a4bb4a1b638e")
        r = S.sbom_from_spdx(p, "p", "1")                   # 0.12.0: refused ("not an SPDX 2.x JSON …")
        self.assertEqual((r.source["wrapper"], r.source["wrapper_predicate_type"]), ("in-toto-statement", "https://spdx.dev/Document"))
        self.assertTrue(r.source["schema_check"].startswith("conformant to spdx-schema-v2.3.1.json"))
        self.assertEqual(r.source["sha256"], "3ed77f6d576a9f4986e395bb121f294b6359e7727320c89caee6a4bb4a1b638e")
        self.assertGreater(len(S.resolved_components(r)), 100)

    def test_record_and_verify_the_statement_bytes(self):
        from omega_cra_evol import EvidenceLocker
        p = self.load("docker-compose_v5.8.0_darwin-aarch64.sbom.json.gz", "3ed77f6d576a9f4986e395bb121f294b6359e7727320c89caee6a4bb4a1b638e")
        led = os.path.join(self.td, "l.jsonl")
        lk = EvidenceLocker(led, "p", "1")
        e = lk.record_sbom(S.sbom_from_spdx(p, "p", "1"), source_path=p)
        self.assertTrue(e["data"]["sbom_floor_met"])

    def test_a_repeated_spdxid_in_a_real_document_is_refused(self):
        """positive control on a real document: the k9s SPDX document with one SPDXID repeated"""
        p = self.load("k9s_v0.51.0_Darwin_amd64.tar.gz.sbom.json.gz", "4e8c27a168097842772b6b6be72a7d45b1ac67140fa672414f68ac8f5e2f93fa")
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        d["packages"][1]["SPDXID"] = d["packages"][0]["SPDXID"]
        with self.assertRaises(ValueError) as cm:
            self.spdx(d)
        self.assertIn("SPDXID unique", str(cm.exception))


@unittest.skipUnless(os.environ.get("CRA_REAL_NET") == "1" and HAVE_SCHEMA, "network test: CRA_REAL_NET=1")
class RealNetwork(Docs):
    """the documents whose licence does not allow keeping a copy here: fetched by URL, checked by sha256"""

    def test_each(self):
        with open(os.path.join(REAL, "NETWORK.tsv"), encoding="utf-8") as f:
            rows = [ln.rstrip("\n").split("\t") for ln in f if ln.strip() and not ln.startswith("#")]
        for url, sha, flag, want in rows:
            with urllib.request.urlopen(url, timeout=120) as r:       # nosec B310 - fixed https URLs of this file
                raw = r.read()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), sha, url)
            p = self.write(raw.decode("utf-8"), "n.json")
            fn = S.sbom_from_cyclonedx if flag == "cyclonedx" else S.sbom_from_spdx
            try:
                r = fn(p, "p", "1")
                got = "accepted" + "".join(f" {x['section']}" for x in r.source.get("spec_rules", []))
            except ValueError as e:
                got = "refused: " + str(e)
            self.assertTrue(got.startswith(want), (url, got))


if __name__ == "__main__":
    unittest.main()

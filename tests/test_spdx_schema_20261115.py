# SPDX-License-Identifier: AGPL-3.0-or-later
"""An SPDX document is checked against the official schema of the version it declares (CHANGELOG, 0.11.0, SPDX
rules 1-5). The controls are other projects' own test inputs (tests/data/spdx_controls, Apache-2.0): spdx/tools-java
`BadJSON.spdx.json` and `SPDXWrongVersion.spdx.json`, sbomqs `spdx-no-timestamp` / `spdx-no-authors` (2.3 without
`created` / with no creator) and `spdx-old-version` (SPDX-2.1). Before this change every one of them was recorded,
floor met. The oracle of the generative test is the official schema read by jsonschema directly."""
import copy
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol import sbom as S  # noqa: E402
from omega_cra_evol.locker import EvidenceLocker  # noqa: E402
from omega_cra_evol.sbom import sbom_from_spdx  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CTL = os.path.join(HERE, "data", "spdx_controls")
FX = os.path.join(HERE, "fixtures", "spdx")
DATA = os.path.join(ROOT, "omega_cra_evol", "data", "spdx")
CTX301 = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

try:
    import jsonschema  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False
NEEDS = unittest.skipUnless(HAVE, "jsonschema not installed: the SPDX schema check cannot run here")


def ctl(name):
    return os.path.join(CTL, name)


def write(tmp, doc, name="d.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return p


def record(path, allow=False, tmp=None):
    tmp = tmp or tempfile.mkdtemp()
    rec = sbom_from_spdx(path, "p", "1", allow_nonconformant=allow)
    lk = EvidenceLocker(os.path.join(tmp, "l.jsonl"), "p", "1")
    return rec, lk.record_sbom(rec, source_path=path)


class TestVendoredSchemas(unittest.TestCase):
    def test_bytes_are_the_ones_named_in_sources(self):
        with open(os.path.join(DATA, "SOURCES.txt"), encoding="utf-8") as f:
            lines = f.read().splitlines()
        want = {ln.split()[1]: ln.split()[0] for ln in lines if len(ln) > 66 and ln[64:66] == "  "}
        self.assertEqual(set(want), {"spdx-schema-v2.2.2-4694d1f.json", "spdx-schema-v2.3.1.json", "spdx-json-schema-3.0.1.json",
                                     "LICENSE-CC-BY-3.0", "LICENSE-Community-Spec-1.0"})
        for name, h in want.items():
            with open(os.path.join(DATA, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), h, name)

    def test_no_format_keyword_in_the_spdx_schemas(self):
        # rule 3: no format checker is needed for SPDX — true only while no schema uses `format`
        def formats(o):
            if isinstance(o, dict):
                return ([o["format"]] if isinstance(o.get("format"), str) else []) + [x for v in o.values() for x in formats(v)]
            return [x for v in o for x in formats(v)] if isinstance(o, list) else []
        for name in ("spdx-schema-v2.2.2-4694d1f.json", "spdx-schema-v2.3.1.json", "spdx-json-schema-3.0.1.json"):
            with open(os.path.join(DATA, name), encoding="utf-8") as f:
                self.assertEqual(formats(json.load(f)), [], name)
        self.assertEqual(formats({"a": [{"format": "uri"}]}), ["uri"])     # positive control of the walker

    def test_the_301_schema_requires_the_string_context(self):
        with open(os.path.join(DATA, "spdx-json-schema-3.0.1.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["properties"]["@context"], {"const": CTX301})


@NEEDS
class TestControls(unittest.TestCase):
    def test_conformant_documents_are_recorded_floor_met(self):
        for name, schema in (("tools-java_SPDXJSONExample-v2.2.spdx.json", "spdx-schema-v2.2.2-4694d1f.json"),
                             ("tools-java_SPDXJSONExample-v2.3.spdx.json", "spdx-schema-v2.3.1.json"),
                             ("tools-java_SPDXJsonLDExample-v3.0.1.json", "spdx-json-schema-3.0.1.json")):
            rec, e = record(ctl(name))
            self.assertEqual(rec.source["schema_check"], "conformant to " + schema, name)
            # the 3.0.1 example of tools-java describes one package and has no other: no resolved component
            self.assertEqual(e["data"]["sbom_floor_met"], "v3" not in name, name)
        for name in sorted(os.listdir(FX)):          # the fixtures the SPDX tests always used: conformant, floor met
            rec, e = record(os.path.join(FX, name))
            self.assertTrue(rec.source["schema_check"].startswith("conformant to "), name)
            self.assertTrue(e["data"]["sbom_floor_met"], name)

    def test_documents_their_authors_call_invalid_are_refused(self):
        for name, where in (("tools-java_BadJSON.spdx.json", "spdx-schema-v2.2.2-4694d1f.json at packages/0"),
                            ("sbomqs_spdx-no-timestamp.json", "spdx-schema-v2.3.1.json at creationInfo"),
                            ("sbomqs_spdx-no-authors.json", "spdx-schema-v2.3.1.json at creationInfo/creators")):
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(ctl(name), "p", "1")
            self.assertIn("SPDX not conformant to " + where, str(cm.exception), name)
            rec, e = record(ctl(name), allow=True)
            self.assertTrue(rec.source["schema_check"].startswith("not conformant to "), name)
            self.assertFalse(e["data"]["sbom_floor_met"], name)
            self.assertGreater(e["data"]["resolved_components"], 0, name)   # the floor fails for the schema alone

    def test_versions_without_a_schema_are_refused(self):
        for name, ver in (("tools-java_SPDXWrongVersion.spdx.json", "'SPDX-2.2.1'"), ("sbomqs_spdx-old-version.json", "'SPDX-2.1'")):
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(ctl(name), "p", "1")
            self.assertIn("no official schema here for spdxVersion " + ver, str(cm.exception))
            rec, e = record(ctl(name), allow=True)
            self.assertTrue(rec.source["schema_check"].startswith("not checked: no official schema here"), name)
            self.assertFalse(e["data"]["sbom_floor_met"], name)

    def test_spdx3_array_context_is_not_301_conformant(self):
        with self.assertRaises(ValueError) as cm:                      # sbomqs: an array holding the 3.0.1 context
            sbom_from_spdx(ctl("sbomqs_v2.1.0-complete-all-fields.json"), "p", "1")
        self.assertIn("spdx-json-schema-3.0.1.json at @context", str(cm.exception))
        with tempfile.TemporaryDirectory() as tmp:                     # the same conformant document, array context
            with open(ctl("tools-java_SPDXJsonLDExample-v3.0.1.json"), encoding="utf-8") as f:
                d = json.load(f)
            self.assertEqual(d["@context"], CTX301)
            for ctx, refused in (([CTX301], True), ([CTX301, {"ex": "https://example.org/"}], True), (CTX301, False)):
                d["@context"] = ctx
                p = write(tmp, d)
                if refused:
                    self.assertRaises(ValueError, sbom_from_spdx, p, "p", "1")
                    rec, e = record(p, allow=True, tmp=tmp)
                    self.assertTrue(rec.source["schema_check"].startswith("not conformant to spdx-json-schema-3.0.1.json at @context"))
                    self.assertFalse(e["data"]["sbom_floor_met"])
                else:
                    self.assertTrue(sbom_from_spdx(p, "p", "1").source["schema_check"].startswith("conformant"))

    def test_reasons_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(ctl("tools-java_SPDXJSONExample-v2.3.spdx.json"), encoding="utf-8") as f:
                d = json.load(f)
            d["packages"][0]["primaryPackagePurpose"] = "X" * 1000
            rec, _ = record(write(tmp, d), allow=True, tmp=tmp)
            self.assertTrue(rec.source["schema_check"].startswith("not conformant to spdx-schema-v2.3.1.json at packages/0"))
            self.assertEqual(len(rec.source["schema_check"]), 300)
            with open(ctl("tools-java_SPDXJsonLDExample-v3.0.1.json"), encoding="utf-8") as f:
                d = json.load(f)
            d["@context"] = "https://example.org/" + "c" * 300
            rec, _ = record(write(tmp, d), allow=True, tmp=tmp)
            self.assertEqual(rec.source["schema_check"], "not checked: no official schema here for @context "
                             + json.dumps(d["@context"])[:120] + " (SPDX 3.0.1: %r)" % CTX301)

    def test_301_is_checked_as_json_schema_2020_12(self):
        # unevaluatedProperties exists only from 2019-09: a key outside the model in a @graph element is refused
        # (a draft-07 validator would ignore the keyword and accept it)
        with tempfile.TemporaryDirectory() as tmp:
            with open(ctl("tools-java_SPDXJsonLDExample-v3.0.1.json"), encoding="utf-8") as f:
                d = json.load(f)
            d["@graph"][-1]["notInTheModel"] = "x"
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(write(tmp, d), "p", "1")
            self.assertIn("Unevaluated properties are not allowed", str(cm.exception))

    def test_other_spdx3_contexts_have_no_schema_here(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(ctl("tools-java_SPDXJsonLDExample-v3.0.1.json"), encoding="utf-8") as f:
                d = json.load(f)
            for ctx in ("https://spdx.org/rdf/3.0.0/spdx-context.jsonld", "https://spdx.org/rdf/3.1/spdx-context.jsonld",
                        ["https://spdx.org/rdf/3.0.0/spdx-context.jsonld"], None, 5, CTX301 + " ", CTX301.upper()):
                d["@context"] = ctx
                with self.assertRaises(ValueError) as cm:
                    sbom_from_spdx(write(tmp, d), "p", "1")
                self.assertIn("no official schema here for @context", str(cm.exception), ctx)
            d["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
            rec, e = record(write(tmp, d), allow=True, tmp=tmp)
            self.assertEqual(rec.source["schema_check"], "not checked: no official schema here for @context "
                             '"https://spdx.org/rdf/3.0.0/spdx-context.jsonld" (SPDX 3.0.1: %r)' % CTX301)
            self.assertFalse(e["data"]["sbom_floor_met"])
            del d["@context"]
            self.assertRaises(ValueError, sbom_from_spdx, write(tmp, d), "p", "1")

    def test_spdxversion_missing_or_not_a_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(ctl("tools-java_SPDXJSONExample-v2.3.spdx.json"), encoding="utf-8") as f:
                d = json.load(f)
            d["spdxVersion"] = "SPDX-2." + "9" * 100        # the version is quoted in the reason, cut at 40 characters
            with self.assertRaises(ValueError) as cm:
                sbom_from_spdx(write(tmp, d), "p", "1")
            self.assertIn("spdxVersion %r (SPDX-2.2, SPDX-2.3)" % d["spdxVersion"][:40], str(cm.exception))
            for v in (None, 2.3, ["SPDX-2.3"], "SPDX-2.3 ", "spdx-2.3", "SPDX-2.4", "SPDX-3.0"):
                d["spdxVersion"] = v
                with self.assertRaises(ValueError, msg=repr(v)):
                    sbom_from_spdx(write(tmp, d), "p", "1")

    def test_a_forged_schema_check_is_refused(self):
        p = ctl("sbomqs_spdx-no-timestamp.json")
        rec = sbom_from_spdx(p, "p", "1", allow_nonconformant=True)
        rec.source["schema_check"] = "conformant to spdx-schema-v2.3.1.json"
        with tempfile.TemporaryDirectory() as tmp:
            lk = EvidenceLocker(os.path.join(tmp, "l.jsonl"), "p", "1")
            with self.assertRaises(ValueError):
                lk.record_sbom(rec, source_path=p)

    def test_without_jsonschema_the_document_is_recorded_not_checked(self):
        real_import = __import__

        def no_jsonschema(name, *a, **k):
            if name == "jsonschema" or name.startswith("jsonschema."):
                raise ImportError("no jsonschema (test)")
            return real_import(name, *a, **k)
        with mock.patch.dict(S._SPDX_VALIDATORS, clear=True), mock.patch("builtins.__import__", no_jsonschema):
            for name in ("tools-java_SPDXJSONExample-v2.3.spdx.json", "tools-java_BadJSON.spdx.json"):
                rec, e = record(ctl(name))
                self.assertTrue(rec.source["schema_check"].startswith("not checked: jsonschema is not installed"), name)
                self.assertFalse(e["data"]["sbom_floor_met"], name)
            # a version without a schema is refused before the tool is even looked for
            self.assertRaises(ValueError, sbom_from_spdx, ctl("sbomqs_spdx-old-version.json"), "p", "1")


@NEEDS
class TestGenerative(unittest.TestCase):
    """Random mutations of conformant documents (a new key at any level, a wrong type, a removed key, a duplicated list
    item): the ingest never records as conformant what the official schema refuses, and never refuses what it accepts."""

    def oracle(self, d, name, cls):
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            valid = cls(json.load(f)).is_valid(d)
        # SPDX rule 7 (spec/SBOM_INGEST.md, 0.13.0): a 2.x seeAlsos value must also be an RFC 3986 URI (§10.4); the
        # regular expression is tested on its own in test_sbom_ingest_20261118.py
        see_also = [v for e in (d.get("hasExtractedLicensingInfos") or []) if isinstance(e, dict)
                    for v in (e.get("seeAlsos") or [])] if valid and "spdxVersion" in d else []
        return valid and all(isinstance(v, str) and S.URI.fullmatch(v) for v in see_also)

    def paths(self, o, at=()):
        yield at, o
        if isinstance(o, dict):
            for k, v in o.items():
                yield from self.paths(v, at + (k,))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                yield from self.paths(v, at + (i,))

    def mutate(self, d, rnd):
        d = copy.deepcopy(d)
        at, node = rnd.choice(list(self.paths(d)))
        parent = d
        for k in at[:-1]:
            parent = parent[k]
        op = rnd.randrange(5)
        if op == 0 and isinstance(node, dict):
            node["x-unknown-" + str(rnd.randrange(99))] = rnd.choice([1, "a", None, [], {}])
        elif op == 1 and at:
            parent[at[-1]] = rnd.choice([1, "a", None, [], {}, True, 1.5])
        elif op == 2 and at and isinstance(parent, dict):
            del parent[at[-1]]
        elif op == 3 and isinstance(node, list) and node:
            node.append(copy.deepcopy(node[0]))
        elif op == 4 and isinstance(node, str):
            parent[at[-1]] = node + rnd.choice(["\n", " ", "x", ""]) if at else node
        return d

    def test_ingest_agrees_with_the_schema(self):
        import jsonschema
        rnd = random.Random(20261115)
        cases = (("tools-java_SPDXJSONExample-v2.3.spdx.json", "spdx-schema-v2.3.1.json", jsonschema.Draft201909Validator),
                 ("tools-java_SPDXJSONExample-v2.2.spdx.json", "spdx-schema-v2.2.2-4694d1f.json", jsonschema.Draft7Validator),
                 ("tools-java_SPDXJsonLDExample-v3.0.1.json", "spdx-json-schema-3.0.1.json", jsonschema.Draft202012Validator))
        seen = {True: 0, False: 0}
        with tempfile.TemporaryDirectory() as tmp:
            for base, name, cls in cases:
                with open(ctl(base), encoding="utf-8") as f:
                    d0 = json.load(f)
                for i in range(60):
                    d = self.mutate(d0, rnd)
                    if d.get("spdxVersion", "SPDX-2") != d0.get("spdxVersion") or d.get("@context", CTX301) != d0.get("@context", CTX301):
                        continue          # a changed version is the other rule (tested above)
                    ok = self.oracle(d, name, cls)
                    seen[ok] += 1
                    p = write(tmp, d)
                    try:
                        rec = sbom_from_spdx(p, "p", "1")
                        recorded = rec.source["schema_check"] == "conformant to " + name
                    except ValueError as e:
                        recorded = False
                        if ok:            # the schema accepts it: only the parser's own rules may refuse it
                            self.assertNotIn("not conformant", str(e))
                            continue
                    self.assertEqual(recorded, ok, (base, i))
        self.assertGreater(seen[False], 20)      # the mutations do reach refusals
        self.assertGreater(seen[True], 5)        # and conformant documents


@NEEDS
class TestCli(unittest.TestCase):
    def run_cra(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            env["HOME"] = tmp
            led = os.path.join(tmp, "l.jsonl")
            p = subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", "sbom", "--ledger", led, "--product", "p",
                                "--version", "1"] + list(args), capture_output=True, text=True, cwd=ROOT, env=env)
            return p, os.path.exists(led)

    def test_switch_applies_to_spdx(self):
        p, written = self.run_cra("--from-spdx", ctl("tools-java_BadJSON.spdx.json"))
        self.assertEqual((p.returncode, written), (2, False), p.stderr)
        p, written = self.run_cra("--from-spdx", ctl("tools-java_BadJSON.spdx.json"), "--allow-nonconformant")
        self.assertEqual((p.returncode, written), (1, True), p.stderr)
        self.assertTrue(json.loads(p.stdout)["source"]["schema_check"].startswith("not conformant to spdx-schema-v2.2.2-4694d1f.json"))
        p, written = self.run_cra("--from-spdx", ctl("tools-java_SPDXJSONExample-v2.3.spdx.json"))
        self.assertEqual((p.returncode, written), (0, True), p.stderr)
        p, _ = self.run_cra("--installed", "--allow-nonconformant")
        self.assertEqual(p.returncode, 2)
        self.assertIn("--allow-nonconformant applies only to --from-cyclonedx and --from-spdx", p.stderr)


if __name__ == "__main__":
    unittest.main()

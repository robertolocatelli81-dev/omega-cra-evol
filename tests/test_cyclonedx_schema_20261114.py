# SPDX-License-Identifier: AGPL-3.0-or-later
"""A CycloneDX document is checked against the official schema of its version (CHANGELOG, 0.11.0, rules 1-4).

The official CycloneDX test suite (tests/data/cyclonedx_suite_6470e34: all 359 JSON files of 1.2 ... 1.7, Apache-2.0)
is the external oracle: every `valid-*` file is recorded as conformant (but the two of SUITE_JSON_REPEATS_BOM_REF, from
0.13.0), every `invalid-*` (and `skip_invalid-*`) file is refused. On 0.10.0, 135 of the 141 invalid files were recorded and 103 of them as floor met."""
import glob
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol import sbom as S  # noqa: E402
from omega_cra_evol.locker import EvidenceLocker  # noqa: E402
from omega_cra_evol.sbom import sbom_from_cyclonedx  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SUITE = os.path.join(HERE, "data", "cyclonedx_suite_6470e34")
REAL = sorted(glob.glob(os.path.join(HERE, "fixtures", "real_tools", "*cyclonedx*.json")))
VERSIONS = ("1.2", "1.3", "1.4", "1.5", "1.6", "1.7")


def suite_files():
    for v in VERSIONS:
        for f in sorted(glob.glob(os.path.join(SUITE, v, "*.json"))):
            yield v, f


def checker_ready():
    try:
        return S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})[0] != "not_checked"
    except AttributeError:          # before the change: no checker at all, and the tests below must fail, not skip
        return True


# Two `valid-*` JSON files of the suite repeat a bom-ref that their XML twins (same commit) do not repeat; the XML
# schema of every version declares bom-ref unique (xs:unique), so they are refused (spec/SBOM_INGEST.md, rule 5).
SUITE_JSON_REPEATS_BOM_REF = {"valid-formulation-1.5.json": "workspace-1", "valid-citations-1.7.json": "workflow-1"}

NEEDS = unittest.skipUnless(checker_ready(), "jsonschema[format] not installed: the schema check cannot run here")


@NEEDS
class TestOfficialSuite(unittest.TestCase):
    def test_every_file_gets_the_suite_answer(self):
        counts = {"valid": 0, "invalid": 0, "valid_json_repeats_bom_ref": 0}
        for v, f in suite_files():
            name = os.path.basename(f)
            if name in SUITE_JSON_REPEATS_BOM_REF:       # spec/SBOM_INGEST.md, CycloneDX rule 5 (0.13.0)
                with self.assertRaises(ValueError, msg=name) as cm:
                    sbom_from_cyclonedx(f, "p", "1")
                self.assertIn("(bom-ref unique within the BOM): %r appears 2 times" % SUITE_JSON_REPEATS_BOM_REF[name],
                              str(cm.exception))
                counts["valid_json_repeats_bom_ref"] += 1
            elif name.startswith("valid"):
                rec = sbom_from_cyclonedx(f, "p", "1")
                self.assertEqual(rec.source["schema_check"], "conformant to bom-%s.schema.json" % v, name)
                counts["valid"] += 1
            else:
                with self.assertRaises(ValueError, msg=name):
                    sbom_from_cyclonedx(f, "p", "1")
                counts["invalid"] += 1
        self.assertEqual(counts, {"valid": 216, "invalid": 141, "valid_json_repeats_bom_ref": 2})

    def test_refusal_names_schema_and_path(self):
        f = os.path.join(SUITE, "1.6", "invalid-metadata-timestamp-1.6.json")
        with self.assertRaises(ValueError) as cm:
            sbom_from_cyclonedx(f, "p", "1")
        self.assertIn("not conformant to bom-1.6.schema.json at metadata/timestamp", str(cm.exception))


@NEEDS
class TestRecording(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.lk = EvidenceLocker(os.path.join(self.d, "l.jsonl"), "p", "1")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _copy(self, src):
        dst = os.path.join(self.d, os.path.basename(src))
        shutil.copy(src, dst)
        return dst

    def test_real_generators_conformant_and_floor_unchanged(self):
        self.assertGreaterEqual(len(REAL), 4)
        for f in REAL:
            lk = EvidenceLocker(os.path.join(self.d, os.path.basename(f) + ".jsonl"), "tiny-cra-sample", "1.0.0")
            src = self._copy(f)
            if os.path.basename(f).startswith("cdxgen-12.8.4_"):    # bom-ref repeated (spec/SBOM_INGEST.md, rule 5, 0.13.0)
                with self.assertRaises(ValueError) as cm:
                    sbom_from_cyclonedx(src, "tiny-cra-sample", "1.0.0")
                self.assertIn("(bom-ref unique within the BOM): 'pkg:npm/@cyclonedx/cdxgen@12.8.4' appears 2 times",
                              str(cm.exception))
                continue
            rec = sbom_from_cyclonedx(src, "tiny-cra-sample", "1.0.0")
            self.assertTrue(rec.source["schema_check"].startswith("conformant to bom-"), f)
            e = lk.record_sbom(rec, source_path=src)
            self.assertTrue(e["data"]["sbom_floor_met"], f)

    def test_allow_nonconformant_records_flagged_and_never_floor(self):
        src = self._copy(os.path.join(SUITE, "1.6", "invalid-component-type-1.6.json"))
        rec = sbom_from_cyclonedx(src, "p", "1", allow_nonconformant=True)
        self.assertTrue(rec.source["schema_check"].startswith("not conformant to bom-1.6.schema.json at components/0/type"),
                        rec.source["schema_check"])
        self.assertGreater(len(S.resolved_components(rec)), 0)        # it would have met the floor on 0.10.0
        e = self.lk.record_sbom(rec, source_path=src)
        self.assertFalse(e["data"]["sbom_floor_met"])

    def test_a_forged_schema_check_is_refused(self):
        src = self._copy(os.path.join(SUITE, "1.6", "invalid-component-type-1.6.json"))
        rec = sbom_from_cyclonedx(src, "p", "1", allow_nonconformant=True)
        rec.source["schema_check"] = "conformant to bom-1.6.schema.json"
        with self.assertRaises(ValueError):
            self.lk.record_sbom(rec, source_path=src)

    def test_not_checked_without_validator_or_format_checker(self):
        src = self._copy(REAL[0])
        for patcher in (mock.patch.object(S, "_jsonschema", side_effect=ImportError("No module named 'jsonschema'")),
                        mock.patch.object(S, "_FORMATS_NEEDED", S._FORMATS_NEEDED + ("no-such-format",))):
            S._VALIDATORS.clear()
            with patcher:
                rec = sbom_from_cyclonedx(src, "tiny-cra-sample", "1.0.0")
                self.assertTrue(rec.source["schema_check"].startswith("not checked: "), rec.source["schema_check"])
                lk = EvidenceLocker(os.path.join(self.d, "nc%d.jsonl" % id(patcher)), "tiny-cra-sample", "1.0.0")
                e = lk.record_sbom(rec, source_path=src)
                self.assertFalse(e["data"]["sbom_floor_met"])
            S._VALIDATORS.clear()

    def test_unsupported_spec_version_is_not_checked(self):
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.1", "version": 1,
               "components": [{"type": "library", "name": "a", "version": "1"}]}
        p = os.path.join(self.d, "old.json")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        try:
            rec = sbom_from_cyclonedx(p, "p", "1")
        except ValueError:
            return                                                     # refused before the schema step: also never floor
        self.assertTrue(rec.source["schema_check"].startswith("not checked: "))
        e = self.lk.record_sbom(rec, source_path=p)
        self.assertFalse(e["data"]["sbom_floor_met"])


@NEEDS
class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        env = dict(os.environ, HOME=tempfile.mkdtemp(), PYTHONPATH=ROOT)
        return subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", *args], capture_output=True, text=True, env=env)

    def test_refused_by_default_recorded_with_switch(self):
        d = tempfile.mkdtemp()
        try:
            src = os.path.join(d, "bad.json")
            shutil.copy(os.path.join(SUITE, "1.6", "invalid-component-type-1.6.json"), src)
            led = os.path.join(d, "l.jsonl")
            r = self.run_cli("sbom", "--ledger", led, "--product", "p", "--version", "1", "--from-cyclonedx", src)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("not conformant to bom-1.6.schema.json", r.stdout + r.stderr)
            self.assertFalse(os.path.exists(led) and os.path.getsize(led) > 0)
            r = self.run_cli("sbom", "--ledger", led, "--product", "p", "--version", "1", "--from-cyclonedx", src,
                             "--allow-nonconformant")
            self.assertEqual(r.returncode, 1, r.stderr)
            out = json.loads(r.stdout)
            self.assertFalse(out["floor_met"])
            self.assertTrue(out["source"]["schema_check"].startswith("not conformant"))
        finally:
            shutil.rmtree(d, ignore_errors=True)


@NEEDS
class TestGenerated(unittest.TestCase):
    def test_mutated_documents_refuse_with_valueerror_or_pass_conformant(self):
        rnd = random.Random(20261114)
        bases = [json.load(open(f)) for v, f in suite_files() if os.path.basename(f).startswith("valid")][:40]
        junk = [None, 0, -1, 1.5, "", "x", [], {}, True, "2020-13-45T00:00:00Z", "urn:uuid:nope"]
        d = tempfile.mkdtemp()
        try:
            for n in range(1500):
                doc = json.loads(json.dumps(rnd.choice(bases)))
                node = doc
                for _ in range(rnd.randint(0, 3)):              # walk down a random path
                    kids = [k for k, v in (node.items() if isinstance(node, dict) else enumerate(node))
                            if isinstance(v, (dict, list)) and v] if isinstance(node, (dict, list)) else []
                    if not kids:
                        break
                    node = node[rnd.choice(kids)]
                if isinstance(node, dict):
                    if node and rnd.random() < 0.5:
                        node[rnd.choice(list(node))] = rnd.choice(junk)
                    else:
                        node["zz%d" % n] = rnd.choice(junk)
                elif isinstance(node, list):
                    node.append(rnd.choice(junk))
                p = os.path.join(d, "m.json")
                with open(p, "w") as fh:
                    json.dump(doc, fh)
                for allow in (False, True):
                    try:
                        rec = sbom_from_cyclonedx(p, "p", "1", allow_nonconformant=allow)
                    except ValueError:
                        continue
                    sc = rec.source["schema_check"]
                    if not allow:
                        self.assertTrue(sc.startswith("conformant to ") or sc.startswith("not checked: "), sc)
                    else:
                        self.assertRegex(sc, r"^(conformant to |not conformant to |not checked: )")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

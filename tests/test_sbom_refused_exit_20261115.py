# SPDX-License-Identifier: AGPL-3.0-or-later
"""`cra sbom`: a refused document exits 2 with one line on stderr and nothing written; a document in another
serialisation is named (CHANGELOG, 0.11.0). Before, every refusal exited 1 with a traceback — the code of
"recorded, floor not met" — and an SPDX tag-value or CycloneDX XML file was refused as `JSONDecodeError: Expecting value`.
Real processes, HOME and ledger in a temporary folder."""
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol import sbom as S  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CTL = os.path.join(HERE, "data", "spdx_controls")

CDX_XML = ('<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.6" serialNumber='
           '"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1">\n  <components/>\n</bom>\n')
SPDX_RDF = ('<?xml version="1.0" encoding="utf-8"?>\n<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"\n'
            '  xmlns:spdx="http://spdx.org/rdf/terms#">\n  <spdx:SpdxDocument rdf:about="https://example.org/d#SPDXRef-DOCUMENT"/>\n</rdf:RDF>\n')


def cra(tmp, flag, path, *extra):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["HOME"] = tmp
    led = os.path.join(tmp, "l.jsonl")
    p = subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", "sbom", "--ledger", led, "--product", "p", "--version",
                        "1", flag, path] + list(extra), capture_output=True, text=True, cwd=ROOT, env=env)
    written = sorted(x for x in os.listdir(tmp) if x.startswith("l.jsonl"))
    return p, written


class TestRefused(unittest.TestCase):
    def check_refused(self, flag, content, want, binary=False):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "doc")
            with open(src, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as f:
                f.write(content)
            p, written = cra(tmp, flag, src)
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertEqual(written, [])
            self.assertEqual(p.stdout, "")
            lines = p.stderr.splitlines()
            self.assertEqual(len(lines), 1, p.stderr)
            self.assertTrue(lines[0].startswith("cra sbom: refused, nothing recorded: "), lines[0])
            self.assertIn(want, lines[0])
            self.assertNotIn("Traceback", p.stderr)

    def test_spdx_tag_value_is_named(self):
        with open(os.path.join(CTL, "tools-java_SPDXTagExample-v2.3.spdx"), encoding="utf-8") as f:
            tv = f.read()
        for flag in ("--from-spdx", "--from-cyclonedx"):
            self.check_refused(flag, tv, "SPDX tag-value is not supported: give the SPDX JSON document")
        self.check_refused("--from-spdx", "# comment\n\nSPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\n", "SPDX tag-value")
        self.check_refused("--from-spdx", "SPDXVersion SPDX-2.3\n", "document malformed: not JSON")   # not the tag-value form

    def test_xml_is_named(self):
        self.check_refused("--from-cyclonedx", CDX_XML, "CycloneDX XML is not supported: give the CycloneDX JSON document")
        self.check_refused("--from-spdx", SPDX_RDF, "SPDX RDF/XML is not supported: give the SPDX JSON document")
        self.check_refused("--from-cyclonedx", "<html><body>x</body></html>", "document malformed: not JSON (XML)")
        # RDF/XML of another vocabulary, or an XML that only mentions the SPDX namespace, is not named SPDX RDF/XML
        self.check_refused("--from-spdx", SPDX_RDF.replace("spdx.org/rdf", "example.org/rdf"), "document malformed: not JSON (XML)")
        self.check_refused("--from-spdx", '<x a="https://spdx.org/rdf/terms#"/>', "document malformed: not JSON (XML)")

    def test_other_refusals_exit_2(self):
        self.check_refused("--from-cyclonedx", "﻿{}", "byte order mark")
        self.check_refused("--from-cyclonedx", "{]", "document malformed: not JSON")
        self.check_refused("--from-cyclonedx", b"\xff\xfe{\x00}\x00", "not UTF-8", binary=True)
        self.check_refused("--from-cyclonedx", '{"bomFormat": "SPDX"}', "not a JSON object with bomFormat 'CycloneDX'")
        self.check_refused("--from-cyclonedx", '{"a": 1, "a": 2}', "duplicate")
        self.check_refused("--from-spdx", '{"spdxVersion": "SPDX-2.1"}', "no official schema here for spdxVersion 'SPDX-2.1'")
        self.check_refused("--from-spdx", "[1]", "SPDX document is not a JSON object")
        with tempfile.TemporaryDirectory() as tmp:          # a missing file is unusable input too
            p, written = cra(tmp, "--from-spdx", os.path.join(tmp, "absent.json"))
            self.assertEqual((p.returncode, written, len(p.stderr.splitlines())), (2, [], 1), p.stderr)

    def test_a_long_reason_is_cut_at_500_characters(self):
        with tempfile.TemporaryDirectory() as tmp:
            absent = os.path.join(tmp, "d" * 200, "e" * 200, "f" * 200 + ".json")
            p, written = cra(tmp, "--from-spdx", absent)
            prefix = "cra sbom: refused, nothing recorded: "
            self.assertEqual((p.returncode, written), (2, []))
            self.assertEqual(len(p.stderr.rstrip("\n")), len(prefix) + 500, p.stderr)
            self.assertTrue(p.stderr.endswith("\n"))

    def test_recorded_floor_not_met_still_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "b.json")
            with open(src, "w", encoding="utf-8") as f:
                json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}, f)
            p, written = cra(tmp, "--from-cyclonedx", src)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertIn("l.jsonl", written)
            self.assertFalse(json.loads(p.stdout)["floor_met"])

    def test_generated_garbage_is_refused_in_one_line(self):
        rnd = random.Random(1511)
        pieces = ["SPDXVersion:", " SPDX-2.3", "\n", "<", "bom", "cyclonedx.org/schema/bom", "rdf:RDF", "spdx.org/rdf", "{",
                  "}", "[", '"', "#", "﻿", "\r\n", "x", "1", "null", ":"]
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(40):
                text = "".join(rnd.choice(pieces) for _ in range(rnd.randrange(1, 10)))
                try:
                    json.loads(text)
                    continue                    # valid JSON is the other tests' business
                except ValueError:
                    pass
                reason = S._not_json_reason(text.encode("utf-8"), json.JSONDecodeError("x", text, 0))
                self.assertNotIn("\n", reason)
                with self.assertRaises(ValueError) as cm:
                    S.sbom_from_cyclonedx(os.path.join(tmp, "n"), "p", "1", raw=text.encode("utf-8"))
                self.assertNotIn("Expecting", str(cm.exception).split("(")[0])   # the format, or "not JSON", comes first


if __name__ == "__main__":
    unittest.main()

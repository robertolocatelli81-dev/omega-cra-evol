# SPDX-License-Identifier: AGPL-3.0-or-later
"""Review of the schema check (14/11/2026): the cases the first round did not exercise.

- a conformant document with many components is checked in linear time (jsonschema's own uniqueItems compares objects
  pairwise: 4,000 components took 16 s, 20,000 took 679 s through `cra sbom`);
- a document the parser accepts (nesting up to 512) is checkable: the check runs under the same recursion allowance
  as the parser, instead of ending in a RecursionError traceback;
- each of the five asserted formats, when its checker is missing, makes the document "not checked";
- a jsonschema without `registry` (older than 4.18) next to a separate `referencing` is "not checked", not a crash;
- an error at the document's root is placed at "(document)";
- `--allow-nonconformant` is refused outside `--from-cyclonedx`."""
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol import sbom as S  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def checker_ready():
    return S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})[0] != "not_checked"


NEEDS = unittest.skipUnless(checker_ready(), "jsonschema[format-nongpl] >= 4.25 not installed: the schema check cannot run here")


def comp(i):
    return {"type": "library", "name": "c%d" % i, "version": "1", "purl": "pkg:pypi/c%d@1" % i, "bom-ref": "r%d" % i}


@NEEDS
class TestScale(unittest.TestCase):
    def test_twenty_thousand_components_in_linear_time(self):
        d = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [comp(i) for i in range(20000)]}
        t = time.time()
        self.assertEqual(S.cyclonedx_schema_check(d)[0], "conformant")
        self.assertLess(time.time() - t, 60)
        d["components"].append(dict(d["components"][123]))
        st, txt = S.cyclonedx_schema_check(d)
        self.assertEqual(st, "not_conformant")
        self.assertIn("has non-unique elements", txt)

    def test_unique_items_equals_jsonschema(self):
        from jsonschema._utils import uniq
        rnd = random.Random(20261114)
        atoms = [0, 1, 1.0, -0.0, 0.0, True, False, None, "", "1", "a", 2 ** 53, float(2 ** 53), 2 ** 53 + 1, -1]

        def val(depth=0):
            r = rnd.random()
            if depth > 3 or r < 0.5:
                return rnd.choice(atoms)
            if r < 0.75:
                return [val(depth + 1) for _ in range(rnd.randint(0, 3))]
            return {rnd.choice("abc"): val(depth + 1) for _ in range(rnd.randint(0, 3))}

        class V:
            def is_type(self, instance, t):
                return isinstance(instance, list)

        for _ in range(20000):
            arr = [val() for _ in range(rnd.randint(0, 5))]
            if arr and rnd.random() < 0.3:
                arr.append(json.loads(json.dumps(rnd.choice(arr))))
            self.assertEqual(uniq(arr), not list(S._unique_items(V(), True, arr, {})), repr(arr))


@NEEDS
class TestDepth(unittest.TestCase):
    def test_deepest_parsable_nesting_is_checked(self):
        depth = 250                      # 2 levels per nested component: the parser's bound of 512 is just above
        s = ""
        for i in range(depth):
            s += '{"type":"library","name":"c%d","version":"1","components":[' % i
        s += '{"type":"library","name":"leaf","version":"1"}' + "]}" * depth
        raw = ('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[' + s + "]}").encode()
        _, d = S._load_document("deep.json", raw)
        before = sys.getrecursionlimit()
        self.assertEqual(S.cyclonedx_schema_check(d)[0], "conformant")
        self.assertEqual(sys.getrecursionlimit(), before)


@NEEDS
class TestNotChecked(unittest.TestCase):
    def tearDown(self):
        S._VALIDATORS.clear()

    def test_each_format_checker_missing(self):
        import jsonschema
        checkers = jsonschema.Draft7Validator.FORMAT_CHECKER.checkers
        for f in ("date", "date-time", "idn-email", "iri-reference", "uri"):
            S._VALIDATORS.clear()
            with mock.patch.dict(checkers):
                del checkers[f]
                st, txt = S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})
            self.assertEqual(st, "not_checked", f)
            self.assertIn(f, txt)

    def test_jsonschema_without_registry(self):
        import jsonschema

        class Old:
            def __init__(self, schema, format_checker=None):
                pass

        S._VALIDATORS.clear()
        with mock.patch.object(jsonschema.validators, "extend", return_value=Old):
            st, txt = S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})
        self.assertEqual(st, "not_checked")
        self.assertIn("jsonschema too old", txt)


@NEEDS
class TestRootError(unittest.TestCase):
    def test_root_error_is_placed_at_document(self):
        st, txt = S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6", "zz": 1})
        self.assertEqual(st, "not_conformant")
        self.assertTrue(txt.startswith("not conformant to bom-1.6.schema.json at (document): "), txt)


class TestCliSwitch(unittest.TestCase):
    def test_allow_nonconformant_only_with_cyclonedx(self):
        d = tempfile.mkdtemp()
        env = dict(os.environ, HOME=d, PYTHONPATH=ROOT)
        r = subprocess.run([sys.executable, "-m", "omega_cra_evol.cli", "sbom", "--ledger", os.path.join(d, "l.jsonl"),
                            "--product", "p", "--version", "1", "--installed", "--allow-nonconformant"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("--allow-nonconformant applies only to --from-cyclonedx", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(d, "l.jsonl")))


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""`pattern` is read as an ECMA-262 regular expression with the "u" flag (CHANGELOG, Unreleased; JSON Schema draft-07
Validation §4.3, 2020-12 Core §6.4). Before, jsonschema's Python `re.search` accepted, for example, a CycloneDX
serialNumber with a final newline (Python's `$` also matches before a final "\\n"). Oracle: Node's own RegExp (when
`node` is installed) on the shipped patterns and on generated strings."""
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

HERE = os.path.dirname(os.path.abspath(__file__))
CTL = os.path.join(HERE, "data", "spdx_controls")
SN = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
NODE = shutil.which("node")

try:
    import jsonschema  # noqa: F401
    HAVE = S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})[0] != "not_checked"
except ImportError:
    HAVE = False

# the 17 distinct `pattern` values of the shipped schemas (CycloneDX 1.2 ... 1.7 with their companions, SPDX 2.2, 2.3, 3.0.1)
SHIPPED = sorted([
    "^(.*)$", "^(?!_:).+:.+", "^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$",
    "^([a-z]{2})(-[A-Z]{2})?$", "^-?[0-9]+(\\.[0-9]*)?$", "^CRE:[0-9]+-[0-9]+$", "^[-+a-z0-9.]+/[-+a-z0-9.]+$",
    "^[0-9]{4}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-6][0-9]:[0-6][0-9](Z|[+-][0-9]{2}:[0-9]{2})$", "^[A-Z]{2}$",
    "^[A-Za-z0-9][A-Za-z0-9\\-/.()\\s]{0,28}[A-Za-z0-9]$", "^[^\\/]+\\/[^\\/]+$", "^\\d\\d\\d\\d-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$",
    "^_:.+", "^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*#.+$",
    "^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*$",
    "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"])


def shipped():
    pats, pp = set(), 0
    for d in (S._CDX_SCHEMA_DIR, S._SPDX_SCHEMA_DIR):
        for n in sorted(os.listdir(d)):
            if n.endswith(".json"):
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    found, k = S.schema_patterns(json.load(f))
                pats.update(found)
                pp += k
    return pats, pp


class TestTranslation(unittest.TestCase):
    def test_the_shipped_schemas_hold_these_patterns_and_no_patternproperties(self):
        pats, pp = shipped()
        semver = [p for p in pats if p.startswith("^(0|[1-9]\\d*)")]
        self.assertEqual(len(semver), 1)                     # the semver pattern of SPDX 3.0.1, too long to write above
        self.assertEqual(sorted(pats - set(semver)), SHIPPED)
        self.assertEqual(pp, 0)
        for p in pats:
            S.ecma_pattern(p)                                # every one translates
        self.assertEqual(S.schema_patterns({"patternProperties": {"^a": {}}, "x": [{"pattern": "b"}]}), (["b"], 1))
        self.assertEqual(sorted(S.schema_patterns({"pattern": "a", "properties": {"x": {"pattern": "b"}}})[0]), ["a", "b"])

    def test_ecma_meaning_of_the_tokens(self):
        cases = [("^a$", "a\n", False), ("^a$", "a", True), ("\\d", "\u0663", False), ("\\d", "7", True),
                 ("^\\w$", "\u00e9", False), ("^\\w$", "_", True), ("^.$", "\r", False), ("^.$", "\u2028", False),
                 ("^.$", "\U00010000", True), ("^\\s$", "\x85", False), ("^\\s$", "\x1c", False), ("^\\s$", "\u3000", True),
                 ("^\\s$", "\ufeff", True), ("^[\\s]$", "\x0b", True), ("^[\\d]$", "\u0663", False), ("^\\S$", "\x85", True),
                 ("^[^\\/]+\\/[^\\/]+$", "a/b", True), ("^(.*)$", "a\rb", False), ("^(.*)$", "abc\n", False),
                 ("^(?!_:).+:.+", "_:x", False), ("^(?!_:).+:.+", "a:x", True), ("^\\x41\\u0042$", "AB", True)]
        for p, s, want in cases:
            self.assertEqual(bool(S.ecma_pattern(p).search(s)), want, (p, s))

    def test_untranslated_constructs_raise(self):
        for p in ("(a)\\1", "\\bx", "\\p{L}", "(?<=a)b", "(?<!a)b", "(?P<n>a)", "(?i)a", "\\u{41}", "[]", "a\\", "[a",
                  "\\k<n>", "\\cA", "\\0", "\\B", "a\\_"):
            with self.assertRaises(S.EcmaPatternUnsupported, msg=p):
                S.ecma_pattern(p)


    def test_patterns_ecma_refuses_or_reads_otherwise_are_not_checked(self):
        # ECMA-262 with "u" refuses these (SyntaxError) or, for the surrogate escapes, reads a pair as ONE code point;
        # Python's re accepts every one with another meaning: never translated
        for p in ("a{", "a{,3}", "a{3,2}", "x{2", "}", "]", "\\-", "\\ ", "\\#", "\\~", "\\'", "a**", "a*+", "a*??",
                  "a{2}{3}", "^*", "$?", "(?=a)*", "(?!a)+", "|*", "(*)", "[\\d-z]", "[a-\\s]", "[\\w-\\d]",
                  "\\uD83D\\uDE00", "[\\uD83D\\uDE00]", "\\uDE00", "\\uD800", "\\uDFFF", ")", "(a", "[]a]", "[^]a]", "[][a]"):
            with self.assertRaises(S.EcmaPatternUnsupported, msg=p):
                S.ecma_pattern(p)
        for p, s, want in [("^a??$", "", True), ("^a{2}?$", "aa", True), ("^(a)*$", "aa", True), ("^[\\d-]$", "-", True),
                           ("^[-\\d]$", "5", True), ("^[\\-a]$", "-", True), ("^\\/\\{\\}$", "/{}", True),
                           ("^\\x41+$", "AA", True), ("^\\u0041{2}$", "AA", True), ("^a{2,2}$", "aa", True),
                           ("^\\uD7FF$", "\ud7ff", True)]:
            self.assertEqual(bool(S.ecma_pattern(p).search(s)), want, (p, s))

@unittest.skipUnless(HAVE, "jsonschema[format-nongpl] not installed: the schema check cannot run here")
class TestSchemaCheck(unittest.TestCase):
    def test_a_final_newline_is_not_conformant(self):
        base = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
        self.assertEqual(S.cyclonedx_schema_check(dict(base, serialNumber=SN))[0], "conformant")
        st, text = S.cyclonedx_schema_check(dict(base, serialNumber=SN + "\n"))
        self.assertEqual(st, "not_conformant")
        self.assertIn("at serialNumber", text)
        with open(os.path.join(CTL, "tools-java_SPDXJsonLDExample-v3.0.1.json"), encoding="utf-8") as f:
            d = json.load(f)
        self.assertEqual(S.spdx_schema_check(d)[0], "conformant")
        ci = next(e for e in d["@graph"] if e.get("type") == "CreationInfo")
        ci["created"] = ci["created"] + "\n"
        self.assertEqual(S.spdx_schema_check(d)[0], "not_conformant")

    def test_an_untranslatable_pattern_means_not_checked(self):
        with mock.patch.object(S, "_ecma_ready", lambda docs: "pattern 'x': not translated (test)"), \
                mock.patch.dict(S._VALIDATORS, clear=True), mock.patch.dict(S._SPDX_VALIDATORS, clear=True):
            self.assertEqual(S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"}),
                             ("not_checked", "not checked: pattern 'x': not translated (test)"))
            with open(os.path.join(CTL, "tools-java_SPDXJSONExample-v2.3.spdx.json"), encoding="utf-8") as f:
                self.assertEqual(S.spdx_schema_check(json.load(f))[0], "not_checked")
        self.assertIn("patternProperties", S._ecma_ready([{"patternProperties": {"^a": {}}}]))
        self.assertIn("not translated", S._ecma_ready([{"pattern": "\\bx"}]))
        self.assertIsNone(S._ecma_ready([{"pattern": "^a$"}]))


def suite_strings():
    """the distinct strings, keys included, of up to 300 characters in the JSON files of tests/data and examples"""
    found = set()
    for root in (os.path.join(HERE, "data"), os.path.join(os.path.dirname(HERE), "examples")):
        for dp, _, fs in os.walk(root):
            for n in sorted(fs):
                if not n.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(dp, n), encoding="utf-8") as f:
                        stack = [json.load(f)]
                except ValueError:                 # the suite also holds files that are not JSON on purpose
                    continue
                while stack:
                    o = stack.pop()
                    if isinstance(o, dict):
                        stack.extend(o.values())
                        stack.extend(o.keys())
                    elif isinstance(o, list):
                        stack.extend(o)
                    elif isinstance(o, str) and len(o) <= 300:
                        found.add(o)
    return sorted(found)


@unittest.skipUnless(NODE, "node not installed: no ECMA-262 engine to compare with")
class TestAgainstNode(unittest.TestCase):
    def test_generated_strings(self):
        rnd = random.Random(20261115)
        pats = sorted(shipped()[0]) + ["\\d", "\\w", "\\s", ".", "[\\s]", "\\S", "^(.*)$"]
        chars = ["a", "Z", "0", "9", "_", "-", ".", ":", "/", " ", "\t", "\n", "\r", "\x0b", "\x0c", "\x1c", "\x85", "\u00a0",
                 "\u1680", "\u2007", "\u2028", "\u2029", "\u202f", "\u3000", "\ufeff", "\u0663", "\u00e9", "\U0001d7d8", "T", "Z",
                 "urn:uuid:", "_:", "#", "+"]
        cases = []
        for p in pats:
            for _ in range(150):
                cases.append((p, "".join(rnd.choice(chars) for _ in range(rnd.randrange(0, 8)))))
            cases += [(p, "2026-11-15T00:00:00Z"), (p, "2026-11-15T00:00:00Z\n"), (p, SN), (p, SN + "\n")]
        for s in suite_strings():                  # every string (up to 300 characters) of the JSON files of tests/data and
            for p in pats:                         # examples, as it is and with a final newline, against every pattern
                cases += [(p, s), (p, s + "\n")]
        for c in range(0, 0x3100):                 # every code point up to U+30FF through the single-token classes
            if not 0xD800 <= c <= 0xDFFF:
                cases += [("^\\s$", chr(c)), ("^\\d$", chr(c)), ("^\\w$", chr(c)), ("^.$", chr(c))]
        with tempfile.TemporaryDirectory() as tmp:
            js = os.path.join(tmp, "o.js")
            with open(js, "w", encoding="utf-8") as f:
                f.write("const L=require('fs').readFileSync(0,'utf8').split('\\n').filter(Boolean);"
                        "const c=new Map();process.stdout.write(JSON.stringify(L.map(l=>{const [p,s]=JSON.parse(l);"
                        "if(!c.has(p))c.set(p,new RegExp(p,'u'));return c.get(p).test(s);})));")
            inp = "\n".join(json.dumps(c) for c in cases) + "\n"
            r = subprocess.run([NODE, js], input=inp, capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")})
            self.assertEqual(r.returncode, 0, r.stderr)
            theirs = json.loads(r.stdout)
        self.assertEqual(len(theirs), len(cases))
        diff = [(p, s) for (p, s), t in zip(cases, theirs) if bool(S.ecma_pattern(p).search(s)) != t]
        self.assertEqual(diff, [])
        python = [(p, s) for (p, s), t in zip(cases, theirs) if bool(__import__("re").search(p, s)) != t]
        self.assertGreater(len(python), 50)        # positive control: Python's own reading does differ on these cases


    def test_generated_patterns(self):
        # every pattern the translation accepts must be one Node accepts with "u", matching the same strings
        rnd = random.Random(15112026)
        toks = ["a", "b", "-", ".", "^", "$", "|", "(", ")", "(?:", "(?=", "(?!", "[", "]", "[^", "*", "+", "?", "{", "}",
                "{2}", "{1,3}", "{2,}", "{3,1}", "{,2}", "\\d", "\\D", "\\w", "\\W", "\\s", "\\S", "\\-", "\\/",
                "\\.", "\\$", "\\{", "\\]", "\\#", "\\ ", "\\n", "\\x41", "\\u0041", "\\uD83D", "\\uDE00",
                "\\b", "\\0", "/", " ", "\u00e9", "\U0001F600", "\n", "0", "_", ","]
        pats = sorted({"".join(rnd.choice(toks) for _ in range(rnd.randrange(1, 7))) for _ in range(4000)})
        chars = ["a", "b", "-", ".", "A", "0", "_", "/", " ", "\n", "\r", "\u00e9", "\U0001F600", "\ud83d", "\u2028",
                 "\u00a0", "\ufeff", "\x85", "{", "}", "]", "#", ","]
        strs = sorted({"".join(rnd.choice(chars) for _ in range(rnd.randrange(0, 5))) for _ in range(60)})
        ours = {}
        for p in pats:
            try:
                r = S.ecma_pattern(p)
            except S.EcmaPatternUnsupported:
                continue
            ours[p] = "".join("1" if r.search(s) else "0" for s in strs)
        self.assertGreater(len(ours), 300)
        with tempfile.TemporaryDirectory() as tmp:
            js = os.path.join(tmp, "o.js")
            with open(js, "w", encoding="utf-8") as f:
                f.write("const [P,S]=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify("
                        "P.map(p=>{let r;try{r=new RegExp(p,'u')}catch(e){return null}return S.map(s=>r.test(s)?'1':'0')"
                        ".join('')})));")
            keys = sorted(ours)
            r = subprocess.run([NODE, js], input=json.dumps([keys, strs]), capture_output=True, text=True,
                               env={"PATH": os.environ.get("PATH", "")})
            self.assertEqual(r.returncode, 0, r.stderr)
            theirs = dict(zip(keys, json.loads(r.stdout)))
        self.assertEqual([p for p in keys if theirs[p] != ours[p]], [])

if __name__ == "__main__":
    unittest.main()

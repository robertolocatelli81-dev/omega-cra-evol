# SPDX-License-Identifier: AGPL-3.0-or-later
"""`iri-reference` in linear time (CHANGELOG, 0.11.0): a regular expression of the RFC 3987 §2.2 ABNF replaces the
Earley parser of rfc3987-syntax. Same answer as rfc3987-syntax on every string the official CycloneDX suite checks as
iri-reference and on generated strings, except the three classes where rfc3987-syntax departs from the RFC; time
measured on 20,000 URLs through the CycloneDX schema check (rfc3987-syntax: about 0.1 s per URL)."""
import json
import os
import random
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol import sbom as S  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(HERE, "data", "cyclonedx_suite_6470e34")

try:
    from rfc3987_syntax import is_valid_syntax as _lark
    HAVE_LARK = True
except ImportError:
    HAVE_LARK = False
try:
    import jsonschema
    HAVE_JS = S.cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})[0] != "not_checked"
except ImportError:
    HAVE_JS = False

# where rfc3987-syntax 1.1.0 departs from RFC 3987 §2.2 (it refuses these valid IRI references)
RFC_ONLY = ["http://[::1]/", "http://[1::]/", "http://[1:2::3]/", "http://[::ffff:192.0.2.1]/", "//[fe80::1]",
            "http://[V1.x]/", "http://ex.org/\U00010000", "http://ex.org/?\U000F0000", "\U00020000"]


def iri_strings():
    """every string the official suite gives to the iri-reference format, collected through jsonschema itself"""
    from referencing import Registry, Resource
    sd = S._CDX_SCHEMA_DIR
    docs = {}
    for n in os.listdir(sd):
        if n.endswith(".schema.json"):
            with open(os.path.join(sd, n), encoding="utf-8") as fh:
                docs[n] = json.load(fh)
    reg = Registry().with_resources([(n, Resource.from_contents(d)) for n, d in docs.items()]
                                    + [(d["$id"], Resource.from_contents(d)) for d in docs.values() if isinstance(d.get("$id"), str)])
    seen = set()
    fc = jsonschema.FormatChecker()
    fc.checkers = dict(jsonschema.Draft7Validator.FORMAT_CHECKER.checkers)
    fc.checkers["iri-reference"] = (lambda s: seen.add(s) or True if isinstance(s, str) else True, ())
    for v in os.listdir(SUITE):
        if not os.path.isdir(os.path.join(SUITE, v)):
            continue
        val = jsonschema.Draft7Validator(docs[f"bom-{v}.schema.json"], registry=reg, format_checker=fc)
        for f in sorted(os.listdir(os.path.join(SUITE, v))):
            with open(os.path.join(SUITE, v, f), "rb") as fh:
                try:
                    d = json.loads(fh.read().decode("utf-8"))
                except ValueError:
                    continue
            for _ in val.iter_errors(d):
                pass
    return seen


class TestRfc3987(unittest.TestCase):
    def test_examples(self):
        good = ["http://example.com/a/b?c=d#e", "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "", "#frag", "?q", "a/b",
                "//host:8080/p", "mailto:a@b.c", "http://例え.テスト/パス", "http://1.2.3.4/", "http://u:p@h/", "a:", "./x:y",
                "http://ex.org/%20", "http://[2001:db8::7]/", "file:///etc/hosts"] + RFC_ONLY
        bad = ["a b", "http://ex.org/%zz", "http://ex.org/%2", "http://a\n", "\n", "http://ex.org/\x7f", "http://ex.org/<>",
               ":a", "1a:b", "http://[::1", "http://[g::1]/", "http://ex.org/#a#b", "http://ex.org/\ud800", "a\\b",
               "http://ex.org/?\U000F0000#\U000F0000", "git@github.com:indutny/asn1.js", "http://[1:2:3:4:5:6:7:8:9]/"]
        for s in good:
            self.assertTrue(S.is_iri_reference(s), repr(s))
        for s in bad:
            self.assertFalse(S.is_iri_reference(s), repr(s))
        self.assertTrue(S.is_iri_reference(5))           # not a string: not this format's business

    def test_the_library_checker_is_not_modified(self):
        if not HAVE_JS:
            self.skipTest("jsonschema not installed")
        before = jsonschema.Draft7Validator.FORMAT_CHECKER.checkers["iri-reference"]
        fc = S._format_checker(jsonschema)
        self.assertIs(jsonschema.Draft7Validator.FORMAT_CHECKER.checkers["iri-reference"], before)
        self.assertEqual(fc.checkers["iri-reference"][0], S.is_iri_reference)
        for f in S._FORMATS_NEEDED:
            if f != "iri-reference":
                self.assertIs(fc.checkers[f], jsonschema.Draft7Validator.FORMAT_CHECKER.checkers[f])

    def test_ipv6_literals_against_ipaddress(self):
        """RFC 3986 §3.2.2 IPv6address against the standard library's reading of RFC 4291 text forms (zone identifiers,
        which IP-literal does not admit, are left out): random groups, separators and embedded IPv4 addresses"""
        import ipaddress
        rnd = random.Random(3986)
        hexes = ["", "0", "1", "ab", "ffff", "12345", "g", "0db8"]
        quads = ["1.2.3.4", "255.255.255.255", "256.1.1.1", "1.2.3.256", "01.2.3.4", "1.2.3", "250.251.252.253"]
        checked = {True: 0, False: 0}
        for i in range(4000):
            parts = [rnd.choice(hexes) for _ in range(rnd.randrange(1, 10))]
            s = ":".join(parts)
            if rnd.random() < 0.4:
                k = rnd.randrange(len(parts) + 1)
                s = ":".join(parts[:k]) + "::" + ":".join(parts[k:])
            if rnd.random() < 0.3:
                s = s + (":" if s and not s.endswith(":") else "") + rnd.choice(quads)
            try:
                ipaddress.IPv6Address(s)
                want = "%" not in s
            except ValueError:
                want = False
            checked[want] += 1
            self.assertEqual(S.is_iri_reference("http://[%s]/" % s), want, s)
        for s in ("1:2:3:4:5:6:7:8", "::", "::1", "1::", "1:2:3:4:5:6::", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8",
                  "1::3:4:5:6:7:8", "1:2::4:5:6:7:8", "1:2:3::5:6:7:8", "1:2:3:4::6:7:8", "1:2:3:4:5::7:8",
                  "1:2:3:4:5:6::8", "::ffff:1.2.3.255", "1:2:3:4:5:6:1.2.3.4", "::1:2:3:4:5:1.2.3.4"):
            self.assertTrue(S.is_iri_reference("http://[%s]/" % s), s)
        for s in ("1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "12345::", "::ffff:1.2.3.256", "1::2::3", "1:2:3:4:5:6:7:1.2.3.4",
                  "::1:2:3:4:5:6:1.2.3.4", ":1::", "1:::2", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8"):
            self.assertFalse(S.is_iri_reference("http://[%s]/" % s), s)
        self.assertGreater(checked[True], 300)
        self.assertGreater(checked[False], 300)

    def test_linear_time_on_adversarial_strings(self):
        n = 200_000
        for s in ("a" * n + " ", "/" * n + " ", "%41" * (n // 3) + "%", "http://" + "a:" * (n // 2) + " ", "[" + "1:" * n,
                  "http://h/" + "a/" * (n // 2) + "\x00", "?" + "?/" * (n // 2) + "#", "a@" * (n // 2) + ":x ", ":" * n):
            t = time.perf_counter()
            S.is_iri_reference(s)
            self.assertLess(time.perf_counter() - t, 2.0, s[:20])


@unittest.skipUnless(HAVE_LARK and HAVE_JS, "rfc3987-syntax / jsonschema not installed: no second implementation here")
class TestSameAnswer(unittest.TestCase):
    def test_every_suite_string(self):
        strings = iri_strings()
        self.assertGreater(len(strings), 50)
        diff = [s for s in strings if S.is_iri_reference(s) != _lark("iri_reference", s)]
        self.assertEqual(diff, [])

    def test_generated_strings(self):
        rnd = random.Random(15112026)
        alphabet = list("aZ09-._~!$&'()*+,;=:@/?#[]%vV") + ["%41", "%g1", "::", "1:", " ", "", " ", "\n", "\\",
                                                         "\U00010000", "\U000F0000", "é", "\x7f", "http://", "//", "[::1]"]
        departs = 0
        for i in range(3000):
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 12)))
            mine, theirs = S.is_iri_reference(s), _lark("iri_reference", s)
            if mine != theirs:
                # only where rfc3987-syntax refuses what the RFC accepts (IPv6 short forms, supplementary planes, "V")
                self.assertTrue(mine and not theirs, repr(s))
                self.assertTrue(any(c in s for c in ("::", "\U00010000", "\U000F0000", "V", "[")), repr(s))
                departs += 1
        for s in RFC_ONLY:
            self.assertFalse(_lark("iri_reference", s), repr(s))     # the departures are real, not ours


@unittest.skipUnless(HAVE_JS, "jsonschema not installed: the schema check cannot run here")
class TestTime(unittest.TestCase):
    def test_20000_urls_through_the_schema_check(self):
        comps = [{"type": "library", "name": f"c{i}", "version": "1", "bom-ref": f"r{i}",
                  "externalReferences": [{"type": "website", "url": f"https://example.org/p/{i}?q={i}#f"},
                                         {"type": "vcs", "url": f"git+https://example.org/r{i}.git"}]} for i in range(10_000)]
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "b.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            t = time.perf_counter()
            rec = S.sbom_from_cyclonedx(p, "p", "1")
            took = time.perf_counter() - t
        self.assertEqual(rec.source["schema_check"], "conformant to bom-1.6.schema.json")
        self.assertLess(took, 120.0)          # rfc3987-syntax: ~0.1 s per URL, about 2,000 s for these 20,000


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security review of commit 034ed13 (0.13.0), 20/11/2026: text of a third party read in a time that grew with the
square of its length, and a file written through a name anybody could prepare. Each section below names the defect,
the rule (spec/SBOM_INGEST.md, amendment of 20/11/2026, where the defect is in the ingest) and what was measured on
034ed13 with these same tests (the positive control: copied next to that commit's package, the tests named fail).

Where a procedure replaces an expression, the expression of 0.13.0 is kept HERE as the reference and the two are
compared on every short string over the characters the expression decides on, on seeded random strings and on the
strings of the documents in tests/fixtures with changes applied to them. Where time is the defect, the work is done in
a child process that must end within CEILING seconds, so that code that does not end fails instead of holding the
suite."""
import glob
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from omega_cra_evol import sbom  # noqa: E402

CEILING = 30          # seconds for one child process (the linear readings below take under 1 s, measured 20/11/2026)
MEGABYTE = 1_000_000


def fixture_strings():
    """supplier / originator values and creators items of every SPDX JSON document under tests/fixtures and examples"""
    agents, creators = set(), set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("supplier", "originator") and isinstance(v, str):
                    agents.add(v)
                if k == "creators" and isinstance(v, list):
                    creators.update(x for x in v if isinstance(x, str))
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    for base in ("tests/fixtures", "examples"):
        for p in glob.glob(os.path.join(ROOT, base, "**", "*.json"), recursive=True):
            try:
                with open(p, encoding="utf-8") as f:
                    walk(json.load(f))
            except ValueError:
                pass
    return sorted(agents), sorted(creators)


def changed(rnd, s, pieces):
    """one change to a real string: a piece inserted, a character removed, a piece appended or put in front"""
    k = rnd.randrange(5)
    i = rnd.randrange(len(s) + 1)
    if k == 0:
        return s[:i] + rnd.choice(pieces) + s[i:]
    if k == 1 and s:
        return s[:i] + s[i + 1:]
    if k == 2:
        return s + rnd.choice(pieces)
    if k == 3:
        return rnd.choice(pieces) + s
    return s[:i] + rnd.choice(pieces) + s[i:] + rnd.choice(pieces)


def spdx_document(tool="syft-1.52.0", supplier="Organization: Acme", originator=None):
    b = {"SPDXID": "SPDXRef-b", "name": "b", "versionInfo": "2", "downloadLocation": "NOASSERTION", "supplier": supplier}
    if originator is not None:
        b["originator"] = originator
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
            "documentNamespace": "https://example.com/x",
            "creationInfo": {"created": "2026-11-20T00:00:00Z", "creators": ["Tool: " + tool]},
            "packages": [{"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1", "downloadLocation": "NOASSERTION"}, b],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-a"}]}


def run_child(code, *args, ceiling=CEILING):
    """run `code` in a child interpreter that sees this tree; (ended in time, stdout). The child is killed at the
    ceiling: an expression that does not end cannot hold the suite."""
    env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    try:
        p = subprocess.run([sys.executable, "-B", "-c", code, *args], env=env, capture_output=True, text=True, timeout=ceiling)
    except subprocess.TimeoutExpired:
        return False, ""
    return p.returncode == 0, p.stdout.strip() + p.stderr.strip()[-300:]


INGEST = """
import json, sys
from omega_cra_evol.sbom import sbom_from_spdx
r = sbom_from_spdx(sys.argv[1], "prod", "1.0")
print(json.dumps([r.source["generator"][:20], r.source["generator_version"][:20], [c.supplier[:20] for c in r.components]]))
"""


class Ingests(unittest.TestCase):
    """a document of more than 1 MB, ingested in a child process within the ceiling"""

    def ingest(self, **fields):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)        # 1 MB each: nothing is left in the temporary folder
        p = os.path.join(d, "big.spdx.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(spdx_document(**fields), f)
        self.assertGreater(os.path.getsize(p), MEGABYTE)
        ok, out = run_child(INGEST, p)
        self.assertTrue(ok, f"not ingested within {CEILING} s: {out}")
        return json.loads(out)


# ── 1. the name and the version of the tool (rules 12 and 13(2)) ────────────────────────────────────────────────────
# 034ed13, omega_cra_evol/sbom.py 1480-1482: re.match(r"^(.*?)[-\s]?(\d+\.\d+[\w.\-]*)$", generator). Measured there on
# 20/11/2026: a `Tool:` item of 48 kB ("1.1" repeated, then "!") took 22.7 s.
# With the package of 034ed13 (20/11/2026): LinearTimeTool fails in _digits, _digits_and_dots and _that_is_a_version
# (the child is stopped at the ceiling) and passes in _separators (that shape was not quadratic there); the tests of
# GeneratorSameAsBefore that call the new function end in error (it did not exist), its ingest test passes.
def generator_0130(text):
    gv = re.match(r"^(.*?)[-\s]?(\d+\.\d+[\w.\-]*)$", text)
    return (gv.group(1).rstrip("-"), gv.group(2)) if gv else (text, "")


class GeneratorSameAsBefore(unittest.TestCase):
    """rule 13(2): the name and the version of the tool"""

    def same(self, s):
        self.assertEqual(sbom._generator_name_version(s), generator_0130(s), repr(s))

    def test_examples_of_the_rule(self):
        for text, want in (("syft-1.52.0", ("syft", "1.52.0")), ("trivy-0.74.0", ("trivy", "0.74.0")),
                           ("LicenseFind-1.0", ("LicenseFind", "1.0")),                    # SPDX 2.3.1 §6.8.3
                           ("spdx-maven-plugin", ("spdx-maven-plugin", "")), ("Parlay", ("Parlay", "")), ("", ("", "")),
                           ("tool 1.2", ("tool", "1.2")), ("tool1.2", ("tool", "1.2")), ("tool--1.2", ("tool", "1.2")),
                           ("tool -1.2", ("tool ", "1.2")), ("tool- 1.2", ("tool", "1.2")), ("1.2", ("", "1.2")),
                           ("-1.2", ("", "1.2")), ("tool-1.2-rc.1_x", ("tool", "1.2-rc.1_x")), ("tool-1.2 beta", ("tool-1.2 beta", "")),
                           ("tool-1.2+b", ("tool-1.2+b", "")), ("tool-1", ("tool-1", "")), ("tool-1.", ("tool-1.", "")),
                           ("tool-1.x", ("tool-1.x", "")), ("a-1.2-3.4", ("a", "1.2-3.4")), ("a 1.2 3.4", ("a 1.2", "3.4")),
                           ("12.34", ("", "12.34")), ("x12.34", ("x", "12.34")), ("tool-1.2\n", ("tool", "1.2")),
                           ("tool\n1.2", ("tool", "1.2")), ("to\nol-1.2", ("to\nol-1.2", "")), ("tool-1.2\n\n", ("tool-1.2\n\n", "")),
                           ("tool-٣.٣", ("tool", "٣.٣")), ("tool-².²", ("tool-².²", ""))):
            self.assertEqual(sbom._generator_name_version(text), want, text)
            self.same(text)

    def test_every_short_string(self):
        n = 0
        for alphabet, longest in (("1.-a \n!", 7), ("1._٣²\x1c\ré", 6)):
            for length in range(longest + 1):
                for t in itertools.product(alphabet, repeat=length):
                    self.same("".join(t))
                    n += 1
        self.assertEqual(n, sum(7 ** k for k in range(8)) + sum(8 ** k for k in range(7)))

    def test_random_strings(self):
        rnd = random.Random(20261120)
        pieces = ["1", "23", ".", "-", "_", " ", "\t", "\n", "\r", "\x1c", " ", " ", "a", "é", "٣", "²", "Ⅷ",
                  "!", "+", "(", ":", "syft", "1.52.0", "-1.0", " 1.0", "v", "rc"]
        for _ in range(40000):
            self.same("".join(rnd.choice(pieces) for _ in range(rnd.randrange(12))))

    def test_strings_of_the_fixtures_and_changes_to_them(self):
        _, creators = fixture_strings()
        tools = [sbom._agent_name(c.replace("Tool:", "")) for c in creators if c.startswith("Tool:")]
        self.assertIn("syft-1.52.0", tools)
        self.assertIn("trivy-0.74.0", tools)
        rnd = random.Random(1120)
        pieces = ["1", ".", "-", " ", "\n", "_", "a", "!", "2.0", "-3.1", "٣"]
        for s in tools + creators:
            self.same(s)
            for _ in range(400):
                self.same(changed(rnd, s, pieces))

    def test_the_ingest_reports_the_same_generator_as_0130(self):
        """through sbom_from_spdx: the real generators' documents"""
        got = {}
        for p in sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "real_tools", "*spdx*.json"))):
            src = sbom.sbom_from_spdx(p, "x", "1").source
            got[os.path.basename(p)] = (src["generator"], src["generator_version"])
        self.assertEqual(got, {"syft-1.52.0_spdx-2.3.json": ("syft", "1.52.0"), "trivy-0.74.0_spdx-2.3.json": ("trivy", "0.74.0")})


class LinearTimeTool(Ingests):
    def test_tool_of_one_megabyte_digits_and_dots(self):
        self.assertEqual(self.ingest(tool="1.1" * (MEGABYTE // 3) + "!")[:2], ["1.11.11.11.11.11.11.", ""])

    def test_tool_of_one_megabyte_digits(self):
        self.assertEqual(self.ingest(tool="1" * MEGABYTE + "!")[:2], ["1" * 20, ""])

    def test_tool_of_one_megabyte_separators(self):
        self.assertEqual(self.ingest(tool="a" + "- " * (MEGABYTE // 2) + "!")[:2], ["a- - - - - - - - - -", ""])
        self.assertEqual(self.ingest(tool="a" + "-" * MEGABYTE + "1.0")[:2], ["a", "1.0"])

    def test_tool_of_one_megabyte_that_is_a_version(self):
        self.assertEqual(self.ingest(tool="tool-" + "1." * (MEGABYTE // 2) + "1")[:2], ["tool", "1.1.1.1.1.1.1.1.1.1."])
        self.assertEqual(self.ingest(tool="tool-" + "1" * MEGABYTE + "-" + "1." * 8 + "1")[:2], ["tool-" + "1" * 15, "1.1.1.1.1.1.1.1.1"])


# ── 2. the name of a supplier or originator (rules 12 and 13(1)) ────────────────────────────────────────────────────
# 034ed13, omega_cra_evol/sbom.py 1220: re.sub(r"\s*\([^()]*@[^()]*\)\s*$", "", v). Measured there on 20/11/2026: a
# supplier of 100 kB ("(", "@" repeated, "x(") took 15.1 s.
# With the package of 034ed13 (20/11/2026): LinearTimeSupplier fails in _at_signs, _white_space and
# test_originator_of_one_megabyte (stopped at the ceiling) and passes in _parentheses (not quadratic there);
# AgentNameSameAsBefore passes there, as it must: the result did not change.
def agent_name_0130(v):
    v = sbom._clean(v)
    for pfx in ("Organization:", "Person:"):
        if v.startswith(pfx):
            v = v[len(pfx):].strip()
    return re.sub(r"\s*\([^()]*@[^()]*\)\s*$", "", v).strip() if v else ""


class AgentNameSameAsBefore(unittest.TestCase):
    """rule 13(1): supplier, originator and the text after `Tool:`"""

    def same(self, s):
        self.assertEqual(sbom._agent_name(s), agent_name_0130(s), repr(s))

    def test_examples_of_the_rule(self):
        for value, name in (("Organization: Acme (Bar) Ltd (x@y.z)", "Acme (Bar) Ltd"), ("Acme (Bar) Ltd", "Acme (Bar) Ltd"),
                            ("Person: Jane Doe (jane.doe@example.com)", "Jane Doe"),      # SPDX 2.3.1 §7.5.3, example 1
                            ("Organization: SPDX (Spdx-tech@lists.spdx.org)", "SPDX"), ("  Organization:   Acme  ", "Acme"),
                            ("Organization: Person: Jane", "Jane"), ("Person: Organization: Jane", "Organization: Jane"),
                            ("Acme (a@b) (c)", "Acme (a@b) (c)"), ("Acme (a@b)(c@d)", "Acme (a@b)"), ("Acme ((a@b)", "Acme ("),
                            ("Acme (a@b))", "Acme (a@b))"), ("(a@b)", ""), ("Acme \t (a@b)", "Acme"), ("Acme (@)", "Acme"),
                            ("Acme ()", "Acme ()"), ("Acme (a@b) ", "Acme"), ("NOASSERTION", ""), ("NONE", ""), ("", ""), ("   ", "")):
            self.assertEqual(sbom._agent_name(value), name, value)
            self.same(value)

    def test_not_a_string_is_no_name(self):
        for v in (None, 0, 1, 1.5, True, [], ["Organization: Acme"], {}, {"name": "Acme"}, b"Organization: Acme"):
            self.assertEqual(sbom._agent_name(v), "")
            self.same(v)

    def test_every_short_string(self):
        n = 0
        for alphabet, longest in (("(@) a\n", 7), ("(@) \x1cé:", 6)):
            for length in range(longest + 1):
                for t in itertools.product(alphabet, repeat=length):
                    self.same("".join(t))
                    n += 1
        self.assertEqual(n, sum(6 ** k for k in range(8)) + sum(7 ** k for k in range(7)))

    def test_random_strings(self):
        rnd = random.Random(20261120)
        pieces = ["(", ")", "@", " ", "\t", "\n", "\r", "\x0b", "\x0c", "\x1c", "\x1f", "\x85", " ", " ", "　", "​",
                  "Organization:", "Person:", "NOASSERTION", "NONE", "a", "é", "Acme", "x@y.z", "(x@y.z)", " (x@y.z)", "()", "(@)"]
        for _ in range(40000):
            self.same("".join(rnd.choice(pieces) for _ in range(rnd.randrange(12))))

    def test_strings_of_the_fixtures_and_changes_to_them(self):
        agents, creators = fixture_strings()
        real = agents + creators + [c.replace("Tool:", "") for c in creators]
        self.assertGreaterEqual(len(agents), 5)
        self.assertGreaterEqual(len(creators), 8)
        rnd = random.Random(1120)
        pieces = ["(", ")", "@", " ", "\n", " (a@b.c)", "(a@b.c) ", "Organization: ", "Person: ", " ", ":"]
        for s in real:
            self.same(s)
            for _ in range(400):
                self.same(changed(rnd, s, pieces))


class LinearTimeSupplier(Ingests):
    def test_supplier_of_one_megabyte_at_signs(self):
        self.assertEqual(self.ingest(supplier="Organization: (" + "@" * MEGABYTE + "x(")[2], ["(" + "@" * 19])

    def test_supplier_of_one_megabyte_white_space(self):
        self.assertEqual(self.ingest(supplier="Organization: a" + " " * MEGABYTE + "b")[2], ["a" + " " * 19])
        self.assertEqual(self.ingest(supplier="Organization: Acme" + " " * MEGABYTE + "(a@b.c)")[2], ["Acme"])

    def test_supplier_of_one_megabyte_parentheses(self):
        self.assertEqual(self.ingest(supplier="Organization: a" + " (@)" * (MEGABYTE // 4) + "x")[2], ["a (@) (@) (@) (@) (@"])
        self.assertEqual(self.ingest(supplier="Organization: a" + "(" * MEGABYTE + "@)")[2], ["a" + "(" * 19])

    def test_originator_of_one_megabyte(self):
        self.assertEqual(self.ingest(supplier="NOASSERTION", originator="Person: (" + "@" * MEGABYTE + "x(")[2], ["(" + "@" * 19])


# ── 3. the ledger's append state is written like every other file ───────────────────────────────────────────────────
# 034ed13, omega_cra_evol/ledger.py 325-329: `<ledger>.append-state.json` (a cache) was written through
# `<ledger>.append-state.json.tmp` opened with open(..., "wb"). Measured there on 20/11/2026: a symlink left at that
# name was followed and the file it pointed to overwritten; a FIFO there blocked the append after the record was
# already in the ledger. It is now written with outputs.write_tmp (a new file of a random name, O_EXCL | O_NOFOLLOW)
# and renamed. NothingCreatedAtAPredictableName is the closed list for the package: an audit hook records every file
# opened with O_CREAT while the package appends, stores a source document, writes a pack, a tip and a signature; each
# is the ledger itself or was created with O_EXCL.
# With the package of 034ed13 (20/11/2026): LedgerStateFile fails in test_symlink_at_the_old_temporary_name_is_not_followed,
# test_fifo_at_the_old_temporary_name_does_not_block_the_append, test_random_objects_at_the_state_names and
# test_state_that_cannot_be_written_is_a_warning_and_the_record_is_kept (the temporary file stayed); the three tests of
# NothingCreatedAtAPredictableName that run the package fail. The other three pass there.
from omega_cra_evol import ledger as L  # noqa: E402

OLD_TMP = L.STATE_SUFFIX + ".tmp"       # the name used until 0.13.0
VICTIM = b"ORIGINAL CONTENT\n"

APPEND_WITH_FIFO = """
import os, sys
from omega_cra_evol.ledger import Ledger, STATE_SUFFIX
led = sys.argv[1]
os.mkfifo(led + STATE_SUFFIX + sys.argv[2])
Ledger(led).append({"kind": "probe"})
Ledger(led).append({"kind": "probe"})
print(Ledger(led).verify()["entries"])
"""


@unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "mkfifo"), "needs symlinks and FIFOs")
class LedgerStateFile(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.led = os.path.join(self.d, "cra.ledger.jsonl")
        self.victim = os.path.join(self.d, "victim.txt")
        with open(self.victim, "wb") as f:
            f.write(VICTIM)

    def victim_bytes(self):
        with open(self.victim, "rb") as f:
            return f.read()

    def test_symlink_at_the_old_temporary_name_is_not_followed(self):
        os.symlink(self.victim, self.led + OLD_TMP)
        L.Ledger(self.led).append({"kind": "probe"})
        self.assertEqual(self.victim_bytes(), VICTIM)
        self.assertTrue(os.path.islink(self.led + OLD_TMP))                       # left as it was found
        self.assertFalse(os.path.islink(self.led + L.STATE_SUFFIX))
        with open(self.led + L.STATE_SUFFIX, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["n"], 1)
        with open(self.led, "rb") as f:                                            # and the state written is used
            self.assertIsNotNone(L._cached_start(self.led, f))

    def test_symlink_at_the_state_name_is_replaced_not_followed(self):
        os.symlink(self.victim, self.led + L.STATE_SUFFIX)
        L.Ledger(self.led).append({"kind": "probe"})
        L.Ledger(self.led).append({"kind": "probe"})
        self.assertEqual(self.victim_bytes(), VICTIM)
        self.assertFalse(os.path.islink(self.led + L.STATE_SUFFIX))
        self.assertEqual(L.Ledger(self.led).verify()["entries"], 2)

    def test_fifo_at_the_old_temporary_name_does_not_block_the_append(self):
        ok, out = run_child(APPEND_WITH_FIFO, self.led, ".tmp")
        self.assertTrue(ok, f"the append did not end within {CEILING} s: {out}")
        self.assertEqual(out, "2")

    def test_no_temporary_file_is_left(self):
        for _ in range(5):
            L.Ledger(self.led).append({"kind": "probe"})
        self.assertEqual(sorted(os.listdir(self.d)), ["cra.ledger.jsonl", "cra.ledger.jsonl" + L.STATE_SUFFIX, "victim.txt"])

    def test_state_that_cannot_be_written_is_a_warning_and_the_record_is_kept(self):
        os.mkdir(self.led + L.STATE_SUFFIX)                                        # the rename over a directory fails
        with self.assertLogs("omega_cra_evol.ledger", level="WARNING") as logs:
            L.Ledger(self.led).append({"kind": "probe"})
        self.assertIn("append state not written", logs.output[0])
        self.assertEqual(os.listdir(self.led + L.STATE_SUFFIX), [])
        self.assertEqual([n for n in os.listdir(self.d) if n.endswith(".tmp")], [])   # the temporary file is removed
        self.assertEqual(L.Ledger(self.led).verify()["entries"], 1)

    def test_random_objects_at_the_state_names(self):
        rnd = random.Random(20261120)
        kinds = ("symlink", "dangling", "directory", "file", "nothing", "nothing")   # (a FIFO: the test above, in a child)
        for case in range(120):
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, True)
            led, victim = os.path.join(d, "l.jsonl"), os.path.join(d, "victim.txt")
            with open(victim, "wb") as f:
                f.write(VICTIM)
            n = 0
            for step in range(rnd.randrange(1, 6)):
                for name in (led + OLD_TMP, led + L.STATE_SUFFIX):
                    kind = rnd.choice(kinds)
                    if kind == "nothing" or os.path.lexists(name) and os.path.isdir(name) and not os.path.islink(name):
                        continue
                    if os.path.lexists(name):
                        os.unlink(name)
                    if kind == "symlink":
                        os.symlink(victim, name)
                    elif kind == "dangling":
                        os.symlink(os.path.join(d, "created-through-the-link"), name)
                    elif kind == "directory":
                        os.mkdir(name)
                    else:
                        with open(name, "wb") as f:
                            f.write(rnd.choice([b"", b"{}", b"\xff", b"[1]"]))
                with self.assertLogs("omega_cra_evol.ledger", level="WARNING") if os.path.isdir(led + L.STATE_SUFFIX) \
                        and not os.path.islink(led + L.STATE_SUFFIX) else _no_logs():
                    e = L.Ledger(led).append({"kind": "probe", "step": step})
                self.assertEqual(e["idx"], n, (case, step))
                n += 1
                with open(victim, "rb") as f:
                    self.assertEqual(f.read(), VICTIM, (case, step))
                self.assertFalse(os.path.lexists(os.path.join(d, "created-through-the-link")), (case, step))
                v = L.Ledger(led).verify()
                self.assertEqual((v["chain_ok"], v["entries"]), (True, n), (case, step))


class _no_logs:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_CREATED = None      # a list while a test records; audit hooks cannot be removed, so this one is switched


def _audit(event, args):
    if _CREATED is not None and event == "open" and isinstance(args[2], int) and args[2] & os.O_CREAT:
        _CREATED.append((os.fsdecode(args[0]) if isinstance(args[0], (str, bytes)) else repr(args[0]), bool(args[2] & os.O_EXCL)))


sys.addaudithook(_audit)


class NothingCreatedAtAPredictableName(unittest.TestCase):
    """Closed list: while the package writes, a file opened with O_CREAT is the ledger (the caller's own file, appended
    to) or is created with O_EXCL — a new file, never what somebody left at a name that can be guessed."""

    def record(self, work):
        global _CREATED
        _CREATED = []
        try:
            work()
            return list(_CREATED)
        finally:
            _CREATED = None

    def check(self, d, led, created, at_least):
        mine = [(p, excl) for p, excl in created if os.path.abspath(p).startswith(d)]
        self.assertGreaterEqual(len(mine), at_least, mine)
        self.assertIn((led, False), mine)                                         # the hook sees the ledger's open: it works
        self.assertEqual([p for p, excl in mine if not excl and p != led], [])

    def test_append(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        led = os.path.join(d, "l.jsonl")
        created = self.record(lambda: [L.Ledger(led).append({"kind": "probe"}) for _ in range(3)])
        self.check(d, led, created, 6)                                            # 3 opens of the ledger, 3 state files

    def test_locker_with_a_source_document_and_a_pack(self):
        from omega_cra_evol.locker import EvidenceLocker
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        led = os.path.join(d, "l.jsonl")
        src = os.path.join(ROOT, "tests", "fixtures", "real_tools", "syft-1.52.0_spdx-2.3.json")

        def work():
            lk = EvidenceLocker(led, "prod", "1.0")
            lk.record_sbom(sbom.sbom_from_spdx(src, "prod", "1.0"), source_path=src)
            lk.evidence_pack(os.path.join(d, "pack.json"))
        created = self.record(work)
        self.check(d, led, created, 6)                              # 2 appends (ledger + state each), the source, the pack
        self.assertTrue(os.path.isfile(os.path.join(d, "pack.json")))
        self.assertEqual(len(os.listdir(led + ".sources")), 1)

    def test_signed_tip_and_signed_pack(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography not installed")
        from omega_cra_evol.locker import EvidenceLocker
        from omega_cra_evol.sbom import SBOMComponent, SBOMRecord
        from omega_cra_evol.signing import keygen, load_key, sign_pack
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        led, key, pack = os.path.join(d, "l.jsonl"), os.path.join(d, "k"), os.path.join(d, "pack.json")

        def work():
            keygen(key)
            lk = EvidenceLocker(led, "prod", "1.0", tip_key=load_key(key))
            lk.record_sbom(SBOMRecord("prod", "1.0", [SBOMComponent("a", "1")]))
            lk.evidence_pack(pack)
            sign_pack(pack, load_key(key), "acme-ci")
        created = self.record(work)
        self.check(d, led, created, 9)             # the key, 2 appends (ledger + state + tip each), the pack, the sidecar
        self.assertIn((key, True), created)
        for name in ("l.jsonl.tip.json", "pack.json", "pack.json.sig.json"):
            self.assertTrue(os.path.isfile(os.path.join(d, name)), name)

    def test_the_hook_reports_a_file_created_without_o_excl(self):
        """the bench can fail: the open of 0.13.0, done here, is reported"""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)

        def work():
            with open(os.path.join(d, "x.tmp"), "wb") as f:
                f.write(b"x")
        self.assertEqual(self.record(work), [(os.path.join(d, "x.tmp"), False)])


if __name__ == "__main__":
    unittest.main()

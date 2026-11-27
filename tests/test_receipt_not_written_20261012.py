# SPDX-License-Identifier: AGPL-3.0-or-later
"""12/10/2026: a receipt that could not be written is exit 74, never the verdict's code.

Measured on 0.5.0 (6113d94): every `cra` subcommand and the four verifiers computed their outcome, failed to write it to
stdout and exited either with the outcome's code — 0 or 1 with nothing on stderr (Python with stdout closed; JS on
/dev/full and on a closed pipe; Go on /dev/full) — or with 120 (Python's own flush at exit, "Exception ignored"), 101 (Rust, `println!`
panicking) and 141 (Go killed by SIGPIPE), none of them in the documented exit codes. The JS verifier also cut a
receipt at 65 536 bytes on a pipe (process.exit() right after console.log).

Real processes only (no mocked write, no shell: tests/_streams.py since 27/11/2026, so macOS and Windows run them
too): each command runs with stdout to a file (the control: the verdict's code and the receipt), to /dev/full (ENOSPC,
Linux), to a pipe whose read end is closed before it starts (EPIPE), read-only, and closed (Python only: Node, Go and Rust reopen fd 1 on /dev/null before the program runs, so
for them that case cannot be told from `>/dev/null`). In every losing case: exit 74 and a `receipt not written:` line
on stderr. A receipt above 64 KiB must arrive whole through a slow pipe. Go and Rust run when CRA_VERIFY_GO /
CRA_VERIFY_RUST name a built binary (the CI verifiers job), Node when `node` is on PATH."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "examples", "self_evidence")
SYFT = os.path.join(ROOT, "tests", "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json")
PY = [sys.executable, "-m", "omega_cra_evol.cli"]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _streams as S  # noqa: E402
HAVE_SIGN = True
try:
    import cryptography  # noqa: F401
except ImportError:
    HAVE_SIGN = False

# each mode: (stdout, stderr) of tests/_streams.py; the ones that need /dev/full exist on Linux only (S.NO_DEVFULL), and
# their equivalents — the pipe whose reader has gone, the closed descriptor — run on every system
MODES = {
    "file": ("file", "file"),
    "devfull": ("devfull", "file"),
    # stdout is a pipe whose read end is closed BEFORE the command starts: every write is EPIPE. A reader that exits on
    # its own races the writer: a small receipt can land in the pipe buffer first (measured on 12/10/2026: the Rust
    # verifier exited 1 once that way).
    "pipe_closed": ("pipe_closed", "file"),
    "closed": ("closed", "file"),
    "readonly": ("readonly", "file"),
    "devfull_noerr": ("devfull", "closed"),        # stderr closed too: still 74, no traceback
    "both_full": ("devfull", "devfull"),           # stderr full too: Python's flush of stderr at exit must not turn 74 into 120
    "pipe_noerr": ("pipe_closed", "closed"),       # the same two cases with the pipe in place of /dev/full: every system
    "both_pipes": ("pipe_closed", "pipe_closed"),
    "slow": ("slow", "file"),
}
LOSING = S.LOSING
LOSING_NOERR = ("pipe_noerr", "both_pipes") + (("devfull_noerr", "both_full") if S.HAVE_DEVFULL else ())


# feeds without network: only the two fetch functions are replaced (canned answers / an OSError), the rest is the real code
FEEDS_OFFLINE = r"""
import sys
from omega_cra_evol import feeds
mode = sys.argv[1]
def post(url, body, timeout):
    if mode == "down": raise OSError("no network (test)")
    return {"results": [{"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2020-0001"]}]} for _ in body["queries"]]}
def get(url, timeout):
    if mode == "down": raise OSError("no network (test)")
    if url == feeds.KEV_URL: return {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
    return [{"id": "EUVD-test", "aliases": "CVE-2021-44228"}]
feeds._post_json, feeds._get_json = post, get
from omega_cra_evol.cli import main
sys.exit(main(["feeds", "CVE-2021-44228"]))
"""


NOTICE_OK = {"awareness_datetime_utc": "2026-09-15T08:00:00Z", "manufacturer_name": "example manufacturer",
             "member_states_available": ["IT"], "notification_type": "Vulnerability", "product_name": "omega-cra-evol",
             "product_version": "0.4.0", "summary": "illustrative payload; never submitted", "title": "example (not a real report)"}


def read(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


def tmps(path):
    """temporaries left next to `path`: `<path>.tmp` (until 13/10) or `<path>.<16 hex>.tmp`"""
    d, base = os.path.split(path)
    return [n for n in os.listdir(d) if n.startswith(base + ".") and n.endswith(".tmp")]


def write_big(d):
    """the pack's `kind` made 200 000 characters long: the receipt (pack-kind FAIL echoes it) is above 64 KiB"""
    p = os.path.join(d, "cra_pack.json")
    with open(p, encoding="utf-8") as f:
        pack = json.load(f)
    pack["kind"] = "x" * 200000
    with open(p, "w", encoding="utf-8") as f:
        json.dump(pack, f)
    return p


def run(argv, mode, W, cwd=ROOT, env=None, fsize=None, stdout_only=False):
    """(exit code, stderr text, stdout bytes or None) of argv, stdout and stderr in `mode` (MODES)"""
    e = dict(os.environ, W=W, **(env or {}))
    e.pop("PYTHONPATH", None)
    out, err = MODES[mode]
    if "devfull" in (out, err) and not S.HAVE_DEVFULL:
        raise unittest.SkipTest(S.NO_DEVFULL)
    rc, got, err_text = S.run(argv, out, err, env=e, cwd=cwd, fsize=fsize, stdout_only=stdout_only)
    return rc, err_text, got if out in ("file", "slow") else None


def altered_example(W, name="se_bad"):
    d = os.path.join(W, name)
    shutil.copytree(EXAMPLE, d)
    p = os.path.join(d, "cra_pack.json")
    with open(p, encoding="utf-8") as f:
        pack = json.load(f)
    pack["product_id"] = "ALTERED"
    with open(p, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=1)
    return d


class ReceiptNotWritten(unittest.TestCase):
    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_receipt_")
        self.addCleanup(shutil.rmtree, self.W, True)

    def check(self, label, cmd, verdict, setup=None, modes=LOSING, env=None):
        """file mode: the verdict's code and a receipt; every losing mode: 74 + one stderr line, whatever the verdict.
        `cmd`: an argv, or a function that returns it after `setup`"""
        argv = lambda: cmd() if callable(cmd) else cmd  # noqa: E731
        if setup:
            setup()
        rc, err, out = run(argv(), "file", self.W, env=env)
        self.assertEqual(rc, verdict, f"{label} file: {err}")
        self.assertTrue(out, f"{label}: no receipt in the control")
        self.assertTrue(out.endswith(b"\n"), f"{label}: the receipt lost its final newline")
        self.assertNotIn("receipt not written", err)
        for mode in modes:
            if setup:
                setup()
            rc, err, _ = run(argv(), mode, self.W, env=env)
            self.assertEqual(rc, 74, f"{label} {mode}: exit {rc}, stderr {err!r}")
            self.assertIn("receipt not written: ", err, f"{label} {mode}")
            self.assertNotIn("Traceback", err, f"{label} {mode}")
            self.assertNotIn("Exception ignored", err, f"{label} {mode}")
        for mode in LOSING_NOERR:
            if setup:
                setup()
            rc, _, _ = run(argv(), mode, self.W, env=env)
            self.assertEqual(rc, 74, f"{label} {mode}: stdout lost AND stderr unusable must still exit 74")

    # ---- the reference CLI: every subcommand that prints an outcome ----
    def py(self, *args):
        return PY + list(args)

    @staticmethod
    def recent():   # awareness a minute ago: no deadline can be overdue during the test (the first one is 24 h away)
        return (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def ledger_args(self):
        return ["--ledger", os.path.join(self.W, "l.jsonl"), "--product", "p", "--version", "1"]

    def fresh_ledger(self):
        for f in os.listdir(self.W):
            if f.startswith("l.jsonl") or f in ("p.json", "drop"):
                p = os.path.join(self.W, f)
                shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)

    @unittest.skipUnless(HAVE_SIGN, "the example pack is signed: verifying it needs cryptography")
    def test_verify_valid_and_invalid(self):
        good = os.path.join(self.W, "se")
        shutil.copytree(EXAMPLE, good)
        bad = altered_example(self.W)
        self.check("verify ok", self.py("verify", os.path.join(good, "cra_pack.json"), "--trust-store", os.path.join(good, "trust.json")), 0)
        self.check("verify bad", self.py("verify", os.path.join(bad, "cra_pack.json"), "--trust-store", os.path.join(bad, "trust.json")), 1)

    def test_verify_not_assessed(self):
        bad = altered_example(self.W, "se_na")
        self.check("verify 77", self.py("verify", os.path.join(bad, "cra_pack.json")), 77, env={"CRA_VERIFY_INJECT_FAULT": "1"})

    def test_sbom_valid_and_invalid(self):
        from omega_cra_evol.sbom import cyclonedx_schema_check
        ready = cyclonedx_schema_check({"bomFormat": "CycloneDX", "specVersion": "1.6"})[0] != "not_checked"
        # without the extra [schema] the document is recorded as not checked and never meets the floor (rule 2): exit 1
        self.check("sbom ok", self.py("sbom", *self.ledger_args(), "--from-cyclonedx", SYFT, "--no-store-source"), 0 if ready else 1,
                   setup=self.fresh_ledger)
        self.check("sbom bad", self.py("sbom", *self.ledger_args(), "--installed", "nonexistentpkgxyz"), 1, setup=self.fresh_ledger)

    def test_sbom_record_kept_when_receipt_lost(self):
        """the record is appended before the receipt is printed: a lost receipt (74) leaves it in the ledger"""
        rc, _, _ = run(self.py("sbom", *self.ledger_args(), "--from-cyclonedx", SYFT, "--no-store-source"), "devfull", self.W)
        self.assertEqual(rc, 74)
        lines = read(os.path.join(self.W, "l.jsonl"), "r").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["data"]["kind"], "cra_sbom")

    def test_vuln_valid_and_invalid(self):
        self.check("vuln ok", self.py("vuln", *self.ledger_args(), "--id", "CVE-2026-0001", "--aware", self.recent()), 0, setup=self.fresh_ledger)
        self.check("vuln bad", self.py("vuln", *self.ledger_args(), "--id", "CVE-2026-0002", "--aware", "2026-09-15T00:00:00Z", "--exploited"), 1, setup=self.fresh_ledger)

    def test_notice_valid_and_invalid(self):
        ok_fields = NOTICE_OK
        bad_fields = {k: v for k, v in ok_fields.items() if k != "title"}   # a required field missing: exit 1
        ok, bad = os.path.join(self.W, "ok.json"), os.path.join(self.W, "bad.json")
        for path, fields in ((ok, ok_fields), (bad, bad_fields)):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(fields, f)
        drop = os.path.join(self.W, "drop")
        self.check("notice ok", self.py("notice", *self.ledger_args(), "--stage", "early_warning", "--fields", ok, "--drop", drop), 0, setup=self.fresh_ledger)
        self.check("notice bad", self.py("notice", *self.ledger_args(), "--stage", "early_warning", "--fields", bad, "--drop", drop), 1, setup=self.fresh_ledger)

    def _ledger_with_event(self):
        self.fresh_ledger()
        subprocess.run(PY + ["vuln", *self.ledger_args(), "--id", "CVE-2026-0001", "--aware", self.recent()], cwd=ROOT, check=True, capture_output=True)

    def test_pack(self):
        self.check("pack", self.py("pack", *self.ledger_args(), "--out", os.path.join(self.W, "p.json")), 0, setup=self._ledger_with_event)

    @unittest.skipUnless(HAVE_SIGN, "seal, keygen and sign need cryptography")
    def test_seal_keygen_sign(self):
        def sealed():
            self._ledger_with_event()
            subprocess.run(PY + ["pack", *self.ledger_args(), "--out", os.path.join(self.W, "p.json")], cwd=ROOT, check=True, capture_output=True)
            sha3 = json.loads(read(os.path.join(self.W, "p.json"), "r"))["pack_sha3"]
            with open(os.path.join(self.W, "sha3"), "w") as f:
                f.write(sha3)
        self.check("seal", lambda: self.py("seal", *self.ledger_args(), "--pack-sha3", read(os.path.join(self.W, "sha3"), "r")), 0, setup=sealed)
        key = os.path.join(self.W, "k.seed")
        rmkey = lambda: os.path.exists(key) and os.unlink(key)
        self.check("keygen", self.py("keygen", key), 0, setup=rmkey)
        se = os.path.join(self.W, "se_sign")
        shutil.copytree(EXAMPLE, se)
        self.check("sign", self.py("sign", os.path.join(se, "cra_pack.json"), "--key", key, "--signer-id", "me"), 0)

    def test_schema(self):
        self.check("schema", self.py("schema", "--template", "early_warning"), 0)
        self.check("schema full", self.py("schema"), 0)

    def test_feeds_offline(self):
        self.check("feeds ok", [sys.executable, "-c", FEEDS_OFFLINE, "up"], 0)
        self.check("feeds down", [sys.executable, "-c", FEEDS_OFFLINE, "down"], 1)

    def test_python_large_receipt_slow_pipe(self):
        """a receipt far above the 64 KiB pipe buffer arrives whole through a slow reader, with the verdict's code"""
        cmd = self.py("verify", write_big(altered_example(self.W, "se_big")))
        rc0, _, ref = run(cmd, "file", self.W)
        self.assertGreater(len(ref), 200000)
        rc, err, got = run(cmd, "slow", self.W)
        self.assertEqual((rc, got), (rc0, ref), err)


class OutputFileNotWritten(unittest.TestCase):
    """the files a subcommand promises — the pack of `pack --out`, the sidecar of `sign`, the drop file of `notice`, the
    seed of `keygen` — follow the same rule: not writable → exit 74 + `receipt not written:`, no traceback, nothing
    half-written left behind, the ledger untouched. On 0.5.0 each case was a traceback with exit 1, and `pack --out`
    naming a directory appended the pack's anchor to the ledger before failing to rename the pack."""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_out_")
        self.addCleanup(shutil.rmtree, self.W, True)
        self.ledger = os.path.join(self.W, "l.jsonl")
        self.args = ["--ledger", self.ledger, "--product", "p", "--version", "1"]
        open(os.path.join(self.W, "notadir"), "w").close()   # a regular file: any path under it is ENOTDIR (root included)
        aware = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        subprocess.run(PY + ["vuln", *self.args, "--id", "CVE-2026-0001", "--aware", aware], cwd=ROOT, check=True, capture_output=True)

    def lines(self):
        return read(self.ledger, "r").splitlines()

    def lost(self, *args):
        before = self.lines()
        r = subprocess.run(PY + list(args), cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 74, f"{args[0]}: exit {r.returncode}, stderr {r.stderr!r}")
        self.assertTrue(r.stderr.startswith("receipt not written: "), r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertEqual(self.lines(), before, f"{args[0]}: the ledger changed")
        return r

    def test_pack_out_unwritable(self):
        self.lost("pack", *self.args, "--out", os.path.join(self.W, "notadir", "p.json"))
        os.mkdir(os.path.join(self.W, "adir"))
        self.lost("pack", *self.args, "--out", os.path.join(self.W, "adir"))
        self.assertEqual(tmps(os.path.join(self.W, "adir")), [])
        # the pack's own bytes refused (a full disk) is in test_receipt_design_20261013.py (`ulimit -f`): since 13/10 the
        # temporary has an unpredictable name, so a symlink to /dev/full planted at `q.json.tmp` is no longer followed
        r = subprocess.run(PY + ["pack", *self.args, "--out", os.path.join(self.W, "ok.json")], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)   # control: the same ledger still packs, and the anchor is appended
        self.assertEqual(len(self.lines()), 2)

    def test_notice_drop_unwritable(self):
        fields = os.path.join(self.W, "f.json")
        with open(fields, "w", encoding="utf-8") as f:
            json.dump(NOTICE_OK, f)
        self.lost("notice", *self.args, "--stage", "early_warning", "--fields", fields, "--drop", os.path.join(self.W, "notadir", "drop"))

    @unittest.skipUnless(HAVE_SIGN, "keygen and sign need cryptography")
    def test_keygen_and_sign_unwritable(self):
        self.lost("keygen", os.path.join(self.W, "notadir", "k.seed"))
        key = os.path.join(self.W, "k.seed")
        subprocess.run(PY + ["keygen", key], cwd=ROOT, check=True, capture_output=True)
        se = os.path.join(self.W, "se")
        shutil.copytree(EXAMPLE, se)
        side = os.path.join(se, "cra_pack.json.sig.json")
        os.unlink(side)
        os.mkdir(side)   # the sidecar's path is taken by a directory
        self.lost("sign", os.path.join(se, "cra_pack.json"), "--key", key, "--signer-id", "me")
        self.assertEqual(tmps(side), [])


class VerifiersReceiptNotWritten(unittest.TestCase):
    """the JS, Go and Rust verifiers: same rule; `>&-` is not tested (their runtime reopens fd 1 on /dev/null)"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_receipt_v_")
        self.addCleanup(shutil.rmtree, self.W, True)
        self.good = os.path.join(self.W, "se")
        shutil.copytree(EXAMPLE, self.good)
        self.bad = altered_example(self.W)
        self.big = write_big(altered_example(self.W, "se_big"))

    def verifiers(self):
        vs = {}
        if shutil.which("node"):
            vs["js"] = ["node", os.environ.get("CRA_VERIFY_JS") or os.path.join(ROOT, "verifiers", "js", "cra-verify.mjs")]
        if os.environ.get("CRA_VERIFY_GO"):
            vs["go"] = [os.environ["CRA_VERIFY_GO"]]
        if os.environ.get("CRA_VERIFY_RUST"):
            vs["rust"] = [os.environ["CRA_VERIFY_RUST"]]
        if not vs:
            self.skipTest("no verifier available (node not on PATH, CRA_VERIFY_GO / CRA_VERIFY_RUST unset)")
        return vs

    def test_each_verifier(self):
        for name, base in self.verifiers().items():
            with self.subTest(verifier=name):
                for label, d, verdict in (("valid", self.good, 0), ("invalid", self.bad, 1)):
                    cmd = base + [os.path.join(d, "cra_pack.json"), "--trust-store", os.path.join(d, "trust.json")]
                    rc, err, out = run(cmd, "file", self.W)
                    self.assertEqual(rc, verdict, f"{name} {label} file: {err}")
                    self.assertTrue(out)
                    self.assertTrue(out.endswith(b"\n"), f"{name} {label}: the receipt lost its final newline")
                    for mode in tuple(m for m in LOSING if m != "closed") + LOSING_NOERR:
                        rc, err, _ = run(cmd, mode, self.W)
                        self.assertEqual(rc, 74, f"{name} {label} {mode}: exit {rc}, stderr {err!r}")
                        if mode not in LOSING_NOERR:
                            self.assertIn("receipt not written: ", err, f"{name} {label} {mode}")

    def test_large_receipt_slow_pipe(self):
        """on 0.5.0 the JS verifier passed 65 536 of 201 502 bytes here (process.exit() right after console.log)"""
        for name, base in self.verifiers().items():
            with self.subTest(verifier=name):
                cmd = base + [self.big]
                rc0, _, ref = run(cmd, "file", self.W)
                self.assertGreater(len(ref), 200000)
                rc, err, got = run(cmd, "slow", self.W)
                self.assertEqual(rc, rc0, f"{name} slow pipe: {err}")
                self.assertEqual(len(got), len(ref), f"{name}: receipt cut on a slow pipe")
                self.assertEqual(got, ref)

    def test_large_receipt_file_size_limit(self):
        """stdout a regular file that refuses past 4 KiB: 74 and the line, never the verdict's code with a cut receipt"""
        cmds = {name: base + [self.big] for name, base in self.verifiers().items()}
        cmds["python"] = PY + ["verify", self.big]
        for name, cmd in cmds.items():
            with self.subTest(verifier=name):
                rc, err, got = run(cmd, "file", self.W, fsize=4096, stdout_only=True)   # Windows: a stdout that cannot grow
                self.assertEqual(rc, 74, f"{name}: exit {rc}, {len(got or b'')} bytes, stderr {err!r}")
                self.assertIn("receipt not written: ", err)


class LedgerNeverHalfWritten(unittest.TestCase):
    """the hash-chained ledger: a line that cannot be written whole is not written at all; a record whose signed tip
    cannot be replaced is 74 (the record IS in the chain), and the pack it anchors is never deleted"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_ledger_")
        self.addCleanup(shutil.rmtree, self.W, True)
        self.ledger = os.path.join(self.W, "l.jsonl")
        self.args = ["--ledger", self.ledger, "--product", "p", "--version", "1"]
        aware = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.aware = aware

    def py(self, *args):
        return PY + list(args)

    def on_volume(self):
        """Windows, no RLIMIT_FSIZE: the ledger moves to the full volume (filled after the setup), where no line fits"""
        self.W = S.volume_dir(self)
        self.ledger = os.path.join(self.W, "l.jsonl")
        self.args = ["--ledger", self.ledger, "--product", "p", "--version", "1"]

    def test_line_cut_by_file_size_limit_leaves_ledger_unchanged(self):
        if not S.HAVE_FSIZE:
            self.on_volume()
        subprocess.run(PY + ["vuln", *self.args, "--id", "CVE-2026-0001", "--aware", self.aware], cwd=ROOT, check=True, capture_output=True)
        before = read(self.ledger)
        self.assertLess(len(before), 2048)
        if not S.HAVE_FSIZE:
            S.fill_volume()
        rc, err, _ = run(self.py("sbom", *self.args, "--from-cyclonedx", SYFT, "--no-store-source"), "file", self.W,
                         fsize=2048 if S.HAVE_FSIZE else None)
        self.assertEqual(rc, 74, err)   # nothing recorded: 74 since 13/10 (exit 1 with a traceback before)
        self.assertEqual(read(self.ledger), before, "half a record was left in the hash-chained ledger")
        if not S.HAVE_FSIZE:
            S.unfill_volume()   # room again for the next record
        subprocess.run(PY + ["vuln", *self.args, "--id", "CVE-2026-0002", "--aware", self.aware], cwd=ROOT, check=True, capture_output=True)
        sys.path.insert(0, ROOT)
        from omega_cra_evol.ledger import Ledger
        self.assertTrue(Ledger(self.ledger).verify()["chain_ok"])

    @unittest.skipUnless(HAVE_SIGN, "the tip is signed: needs cryptography")
    def test_tip_not_written(self):
        key = os.path.join(self.W, "k.seed")
        subprocess.run(PY + ["keygen", key], cwd=ROOT, check=True, capture_output=True)
        a = self.args + ["--tip-key", key]
        subprocess.run(PY + ["vuln", *a, "--id", "CVE-2026-0001", "--aware", self.aware], cwd=ROOT, check=True, capture_output=True)
        tip = self.ledger + ".tip.json"
        os.unlink(tip)
        os.mkdir(tip)   # the tip cannot be replaced
        out = os.path.join(self.W, "p.json")
        r = subprocess.run(PY + ["pack", *a, "--out", out], cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 74, r.stderr)
        self.assertTrue(r.stderr.startswith("receipt not written: "), r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        last = json.loads(read(self.ledger, "r").splitlines()[-1])["data"]
        self.assertEqual(last["kind"], "cra_pack_anchor")
        with open(out, encoding="utf-8") as f:   # 0.5.1 deleted the pack its anchor names
            self.assertEqual(json.load(f)["pack_sha3"], last["anchored_pack_sha3"])
        self.assertEqual(tmps(out), [])
        self.assertEqual(tmps(tip), [])
        r = subprocess.run(PY + ["vuln", *a, "--id", "CVE-2026-0002", "--aware", self.aware], cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 74, r.stderr)
        self.assertEqual(json.loads(read(self.ledger, "r").splitlines()[-1])["data"]["kind"], "cra_vuln")

    def test_stdout_cannot_encode_the_receipt(self):
        """PYTHONIOENCODING=ascii and a non-ASCII path in the receipt: 74 (0.5.0: traceback, exit 1)"""
        subprocess.run(PY + ["vuln", *self.args, "--id", "CVE-2026-0001", "--aware", self.aware], cwd=ROOT, check=True, capture_output=True)
        rc, err, _ = run(self.py("pack", *self.args, "--out", os.path.join(self.W, "pacchetto-\u00fc.json")), "file", self.W, env={"PYTHONIOENCODING": "ascii"})
        self.assertEqual(rc, 74, err)
        self.assertIn("receipt not written: ", err)

    def test_drop_file_never_half_written(self):
        """a drop file cut by a file size limit leaves nothing in the drop folder and the ledger unchanged"""
        subprocess.run(PY + ["vuln", *self.args, "--id", "CVE-2026-0001", "--aware", self.aware], cwd=ROOT, check=True, capture_output=True)
        before = read(self.ledger)
        fields = dict(NOTICE_OK, summary="s" * 3990)   # the SRP maximum is 4000: the payload is above 4 KiB
        fpath = os.path.join(self.W, "f.json")
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(fields, f)
        drop = os.path.join(self.W, "drop")
        if not S.HAVE_FSIZE:   # Windows: the drop folder on the full volume, where the drop file cannot be written
            drop = os.path.join(S.volume_dir(self), "drop")
        os.mkdir(drop)
        if not S.HAVE_FSIZE:
            S.fill_volume()
        rc, err, _ = run(self.py("notice", *self.args, "--stage", "early_warning", "--fields", fpath, "--drop", drop), "file", self.W,
                         fsize=4096 if S.HAVE_FSIZE else None)
        self.assertEqual(rc, 74, err)
        self.assertEqual(os.listdir(drop), [], "a half-written drop file was left")
        self.assertEqual(read(self.ledger), before)

    @unittest.skipUnless(HAVE_SIGN, "keygen needs cryptography")
    def test_keygen_seed_not_written_leaves_no_stub(self):
        key = os.path.join(self.W, "k.seed")
        if not S.HAVE_FSIZE:   # Windows: the seed on the full volume
            key = os.path.join(S.volume_dir(self), "k.seed")
            S.fill_volume()
        rc, err, _ = run(self.py("keygen", key), "file", self.W, fsize=0 if S.HAVE_FSIZE else None)
        self.assertEqual(rc, 74, err)
        if not S.HAVE_FSIZE:
            S.unfill_volume()   # room again: the second keygen below must succeed there
        self.assertFalse(os.path.lexists(key), "an empty seed would block the next keygen (O_EXCL)")
        rc, err, _ = run(self.py("keygen", key), "file", self.W)
        self.assertEqual(rc, 0, err)


if __name__ == "__main__":
    unittest.main()

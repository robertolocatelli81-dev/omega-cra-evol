# SPDX-License-Identifier: AGPL-3.0-or-later
"""13/10/2026: the receipt is written whole — or exit 74 — in the cases the 12/10 tests did not reach.

Measured on the first 0.5.1 commits (fb31ab4) with real processes, Python 3.9.25, 3.11.2 and 3.13.15, Node 22 and 24,
Go and Rust:
- with PYTHONUNBUFFERED=1 (or -u) sys.stdout writes to a raw FileIO, whose short write the text layer drops in
  silence: appended to a file of 1 000 bytes under `ulimit -f 1`, `schema` exited 0 and `verify` 1 with 24 bytes of
  the receipt (so did `feeds`, `keygen`, `sign` and `--help`; `sbom`, `vuln` and `seal` exited 1 with a traceback,
  their ledger line refused first);
- on a NON-BLOCKING stdout that a reader drains late, the Python CLI exited 74 with 65 536 bytes of a 201 502-byte
  receipt in the pipe (the verdict's 1 with them, unbuffered), and so did the Rust verifier (74): a slow reader is not a lost one;
- a usage error, an unreadable trust store or an existing seed with stderr full or its reader gone exited 120
  (Python), 101 (Rust: `eprintln!` panics) or 141 (Go: SIGPIPE on fd 2); with stderr closed the Python usage went to
  STDOUT (exit 1 on 3.9 and 3.11, 2 on 3.13); `cra --version` and `cra --help` on a full stdout exited 120;
- `keygen` on an existing seed printed a traceback;
- the temporary file of a promised file was `<path>.tmp`: a symlink planted there was followed, a FIFO blocked the run;
- a ledger line that could not be written at all exited 1 with a traceback (the code of an overdue deadline or an unmet
  SBOM floor), and so did a source document that could not be stored.

Every case below runs as a real process unless it says "in process"."""
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "examples", "self_evidence")
SYFT = os.path.join(ROOT, "tests", "fixtures", "real_tools", "syft-1.52.0_cyclonedx-1.7.json")
PY = [sys.executable, "-B", "-m", "omega_cra_evol.cli"]
EX_IOERR = 74
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _streams as S  # noqa: E402
NO_FIFO = "Windows has no FIFO in a folder (its named pipes live under \\\\.\\pipe\\ only): a FIFO at a file's own path has no equivalent there"
FSIZE_MODES = ("fsize_cut",) if S.HAVE_FSIZE else ()   # Windows: S.NO_FSIZE
HAVE_SIGN = True
try:
    import cryptography  # noqa: F401
except ImportError:
    HAVE_SIGN = False
UNBUF = {"PYTHONUNBUFFERED": "1"}


def _env(extra=None):
    e = dict(os.environ)
    e.pop("PYTHONPATH", None)
    e.update(extra or {})
    return e


def run(argv, mode, env=None, cwd=ROOT):
    """(exit code, stdout bytes or None, stderr text) of argv with stdout in `mode` (tests/_streams.py: each state made
    with the system's own means)"""
    e = _env(env)
    if mode == "fsize_cut":   # 1 000 bytes already there, limit 1 024: 24 bytes taken, then EFBIG
        return S.run(argv, "file", env=e, cwd=cwd, fsize=1024, pre=b"x" * 1000)
    if mode == "devfull" and not S.HAVE_DEVFULL:
        raise unittest.SkipTest(S.NO_DEVFULL)
    rc, out, err = S.run(argv, mode, env=e, cwd=cwd)
    return rc, (out if mode in ("file", "slow") else None), err


def run_prefilled(argv, env=None):
    """stdout is a NON-BLOCKING pipe already full when the process starts, read only later: the process must wait
    asleep, as on a blocking pipe — alive, and in some 1-second window (from the 1st to the 10th second) under 0.2 s of
    CPU, which a loop retrying EAGAIN never does — and once the pipe is drained the receipt must arrive whole.
    Returns (idle, least CPU in a window, exit code, receipt bytes or None, stderr text)."""
    r, w = os.pipe()
    S.set_nonblocking(w)
    filled = 0
    while True:
        try:
            n = os.write(w, b"P" * 4096)
        except BlockingIOError:
            break
        if not n:   # a Windows non-blocking pipe may take 0 bytes instead of raising
            break
        filled += n
    try:
        p = subprocess.Popen(argv, stdout=w, stderr=subprocess.PIPE, cwd=ROOT, env=_env(env))
    finally:
        os.close(w)
    errs = {}
    t = threading.Thread(target=lambda: errs.setdefault("err", p.stderr.read()))
    t.start()
    idle, windows, t0 = False, [], time.time()
    time.sleep(1.0)
    while p.poll() is None and time.time() - t0 < 10:
        try:
            c0 = S.cpu_seconds(p)
            time.sleep(1.0)
            c1 = S.cpu_seconds(p)
        except OSError:
            break
        if p.poll() is not None:
            break
        windows.append(c1 - c0)
        if c1 - c0 < 0.2:
            idle = True
            break
    chunks = []
    while True:
        b = os.read(r, 1 << 16)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    rc = p.wait(timeout=120)
    t.join()
    p.stderr.close()
    data = b"".join(chunks)
    return idle, min(windows, default=None), rc, data[filled:] if data[:filled] == b"P" * filled else None, errs["err"].decode("utf-8", "replace")


def stderr_lost(argv, cwd=ROOT):
    """argv with stdout to a file and stderr full (Linux), closed, or a pipe whose reader has gone: [(how, exit, stdout)]"""
    res = []
    for how in (("devfull",) if S.HAVE_DEVFULL else ()) + ("closed", "pipe_closed"):
        rc, out, _ = S.run(argv, "file", how, env=_env(), cwd=cwd)
        res.append((how, rc, out))
    return res


def altered_example(W, name, big=False):
    d = os.path.join(W, name)
    shutil.copytree(EXAMPLE, d)
    p = os.path.join(d, "cra_pack.json")
    with open(p, encoding="utf-8") as f:
        pack = json.load(f)
    pack["product_id"] = "ALTERED"
    if big:
        pack["kind"] = "x" * 200000   # the receipt echoes it: above 64 KiB
    with open(p, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=1)
    return p


def verifiers():
    vs = {}
    if shutil.which("node"):
        vs["js"] = ["node", os.environ.get("CRA_VERIFY_JS") or os.path.join(ROOT, "verifiers", "js", "cra-verify.mjs")]
    if os.environ.get("CRA_VERIFY_GO"):
        vs["go"] = [os.path.abspath(os.environ["CRA_VERIFY_GO"])]
    if os.environ.get("CRA_VERIFY_RUST"):
        vs["rust"] = [os.path.abspath(os.path.join(ROOT, os.environ["CRA_VERIFY_RUST"]))]
    return vs


def one_line(err):
    lines = err.splitlines()
    return len(lines) == 1 and lines[0].startswith("receipt not written: ")


class StreamsHarness(unittest.TestCase):
    """positive control of tests/_streams.py on this system: each state is the one named (a harness that left stdout
    writable would let every 74 test above pass for the wrong reason, or fail them all)"""
    PROBE = ("import sys, os\n"
             "if sys.stdout is None: sys.exit(10)\n"
             "d = b'x' * 70000\ntry:\n    while d:\n        d = d[os.write(1, d):]\nexcept OSError as e:\n    sys.exit(20)\n"
             "sys.exit(0)\n")

    def code(self, out, **kw):
        return S.run([sys.executable, "-c", self.PROBE], out, env=_env(), **kw)[0]

    def test_each_state(self):
        self.assertEqual(self.code("file"), 0)
        self.assertEqual(self.code("closed"), 10)
        self.assertEqual(self.code("pipe_closed"), 20)
        self.assertEqual(self.code("readonly"), 20)
        if S.HAVE_DEVFULL:
            self.assertEqual(self.code("devfull"), 20)
        if S.HAVE_FSIZE:
            self.assertEqual(self.code("file", fsize=1024), 20)
        rc, got, _ = S.run([sys.executable, "-c", "import sys; sys.stdout.write('y' * 1000)"], "slow", env=_env())
        self.assertEqual((rc, got), (0, b"y" * 1000))
        self.assertEqual(S.run([sys.executable, "-c", "import sys; sys.exit(0 if sys.stderr is None else 3)"], "file", "closed", env=_env())[0], 0)


class Unbuffered(unittest.TestCase):
    """-u / PYTHONUNBUFFERED: the receipt goes to a raw FileIO that can take part of it without raising"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_unbuf_")
        self.addCleanup(shutil.rmtree, self.W, True)

    def test_every_losing_mode_is_74(self):
        bad = altered_example(self.W, "bad")
        for argv, code in ((PY + ["schema"], 0), (PY + ["schema", "--template", "early_warning"], 0), (PY + ["verify", bad], 1),
                           (PY + ["verify", "nö.json"], 1), (PY + ["--version"], 0), (PY + ["--help"], 0)):
            for env in ({}, UNBUF):
                rc, whole, err = run(argv, "file", env)
                self.assertEqual(rc, code, f"{argv[4:]} {env}: {err[-300:]}")
                self.assertTrue(whole.endswith(b"\n"))
                for mode in S.LOSING + FSIZE_MODES:
                    if mode == "fsize_cut" and len(whole) <= 24:   # `--version` fits in the 24 bytes the file still takes
                        continue
                    rc2, _, err2 = run(argv, mode, env)
                    self.assertEqual(rc2, EX_IOERR, f"{argv[4:]} {env} {mode}: exit {rc2}, stderr {err2[-300:]!r}")
                    self.assertTrue(one_line(err2), f"{argv[4:]} {env} {mode}: {err2[-300:]!r}")

    def test_large_receipt_unbuffered(self):
        argv = PY + ["verify", altered_example(self.W, "big", big=True)]
        rc, whole, _ = run(argv, "file")
        self.assertGreater(len(whole), 200000)
        rc_s, piped, err = run(argv, "slow", UNBUF)
        self.assertEqual((rc_s, piped), (rc, whole), err[-300:])
        for mode in FSIZE_MODES + ("head100",):
            self.assertEqual(run(argv, mode, UNBUF)[0], EX_IOERR, mode)


@unittest.skipUnless(S.NONBLOCKING_PIPE, S.NO_NONBLOCKING_PIPE)
class NonBlockingStdout(unittest.TestCase):
    """a full non-blocking stdout is waited for asleep, never reported as 74 (the reader is slow, not gone)"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_nb_")
        self.addCleanup(shutil.rmtree, self.W, True)
        self.good = os.path.join(self.W, "se")
        shutil.copytree(EXAMPLE, self.good)
        self.bad = altered_example(self.W, "bad")
        self.big = altered_example(self.W, "big", big=True)

    def check(self, label, argv, envs=({},)):
        rc0, whole, _ = run(argv, "file")
        for env in envs:
            idle, cpu, rc, got, err = run_prefilled(argv, env)
            self.assertTrue(idle, f"{label} {env}: not waiting asleep (least CPU in a 1 s window {cpu}, exit {rc}, stderr {err[-300:]!r})")
            self.assertEqual(rc, rc0, f"{label} {env}: stderr {err[-300:]!r}")
            self.assertEqual(got, whole, f"{label} {env}: {len(got or b'')} bytes against {len(whole)}")

    def test_python(self):
        self.check("python bad", PY + ["verify", self.bad], ({}, UNBUF))
        self.check("python big", PY + ["verify", self.big], ({}, UNBUF))
        self.check("python schema", PY + ["schema"], ({}, UNBUF))

    def test_verifiers(self):
        vs = verifiers()
        if not vs:
            self.skipTest("no verifier available")
        for name, base in vs.items():
            with self.subTest(verifier=name):
                self.check(name + " valid", base + [os.path.join(self.good, "cra_pack.json"), "--trust-store", os.path.join(self.good, "trust.json")])
                self.check(name + " big", base + [self.big])


class ReadOnlyStdout(unittest.TestCase):
    """stdout open read-only (`1<file`): the write is EBADF. Rust's std::io::stdout treats EBADF as success — the Rust
    verifier exited with the verdict's code and no receipt (measured 13/10/2026 on fb31ab4); now 74 in all four"""

    def test_each(self):
        W = tempfile.mkdtemp(prefix="cra_ro_")
        self.addCleanup(shutil.rmtree, W, True)
        bad = altered_example(W, "bad")
        cmds = {name: base + [bad] for name, base in verifiers().items()}
        cmds["python"] = PY + ["verify", bad]
        for name, argv in cmds.items():
            with self.subTest(verifier=name):
                rc, _, err = run(argv, "readonly")
                self.assertEqual(rc, EX_IOERR, f"{name}: exit {rc}, stderr {err!r}")
                self.assertTrue(one_line(err), f"{name}: {err!r}")


class UsageAndRefusalsWithStderrLost(unittest.TestCase):
    """a usage error or a refusal keeps its documented code with stderr full, closed or gone, and writes nothing to
    stdout; `--version` and `--help` are the command's output: lost, they are 74"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_usage_")
        self.addCleanup(shutil.rmtree, self.W, True)
        self.good = os.path.join(self.W, "se")
        shutil.copytree(EXAMPLE, self.good)
        self.badtrust = os.path.join(self.W, "trust_bad.json")
        with open(self.badtrust, "w") as f:
            f.write("[1, 2")

    def expect(self, argv, code):
        rc, out, err = run(argv, "file")
        self.assertEqual((rc, out), (code, b""), err)
        self.assertNotIn("Traceback", err)
        self.assertTrue(err.strip(), "the refusal says nothing")
        for how, rc, out in stderr_lost(argv):
            self.assertEqual((rc, out), (code, b""), f"{argv[-3:]} {how}")

    def test_python(self):
        self.expect(PY, 2)
        self.expect(PY + ["verify", "x.json", "--bogus"], 2)
        self.expect(PY + ["sbom", "--ledger", "l.jsonl"], 2)
        self.expect(PY + ["verify", os.path.join(self.good, "cra_pack.json"), "--trust-store", self.badtrust], 2)

    def test_refusal_with_traceback_keeps_exit_1(self):
        """a refusal still printed as a traceback (here `seal` of a digest no pack anchored): exit 1 with stderr full,
        closed or gone too, nothing on stdout (the interpreter's own print of the traceback exited 120)"""
        argv = PY + ["seal", "--ledger", os.path.join(self.W, "l.jsonl"), "--product", "p", "--version", "1", "--pack-sha3", "ab" * 32]
        rc, out, err = run(argv, "file")
        self.assertEqual((rc, out), (1, b""), err)
        self.assertIn("digest is not anchored in this ledger", err)
        for how, rc, out in stderr_lost(argv):
            self.assertEqual((rc, out), (1, b""), how)

    @unittest.skipUnless(HAVE_SIGN, "keygen needs cryptography")
    def test_keygen_existing_seed(self):
        key = os.path.join(self.W, "k.seed")
        subprocess.run(PY + ["keygen", key], cwd=ROOT, check=True, capture_output=True, env=_env())
        with open(key, "rb") as f:
            before = f.read()
        self.expect(PY + ["keygen", key], 1)
        rc, _, err = run(PY + ["keygen", key], "file")
        self.assertEqual(err, f"keygen refused: {key} already exists (an existing key is never overwritten){os.linesep}")   # stderr is a text stream: os.linesep
        with open(key, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_verifiers(self):
        vs = verifiers()
        if not vs:
            self.skipTest("no verifier available")
        for name, base in vs.items():
            with self.subTest(verifier=name):
                self.expect(base, 2)
                self.expect(base + [os.path.join(self.good, "cra_pack.json"), "--trust-store", self.badtrust], 2)

    def test_version_and_help_lost(self):
        for flag in ("--version", "--help"):
            rc, out, err = run(PY + [flag], "file")
            self.assertEqual(rc, 0, err)
            self.assertTrue(out.startswith(b"omega-cra-evol " if flag == "--version" else b"usage: cra "), out[:40])
            for mode in S.LOSING:
                rc, _, err = run(PY + [flag], mode)
                self.assertEqual(rc, EX_IOERR, f"{flag} {mode}: {err!r}")
                self.assertTrue(one_line(err), f"{flag} {mode}: {err!r}")
            for how, rc, out in stderr_lost(PY + [flag]):
                self.assertEqual(rc, 0, f"{flag} {how}")
                self.assertTrue(out, f"{flag} {how}")


class InProcess(unittest.TestCase):
    """main() in process with sys.stdout replaced: a StringIO (no bytes below it), a TextIOWrapper over io.BytesIO
    (pytest's capsys: bytes below, no descriptor) with and without write_through, and after text the caller wrote"""

    def _main(self, stream, argv):
        sys.path.insert(0, ROOT)
        from omega_cra_evol.cli import main
        saved = sys.stdout
        sys.stdout = stream
        try:
            return main(argv)
        finally:
            sys.stdout = saved

    def test_streams(self):
        for make in (io.StringIO, lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True),
                     lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            s = make()
            rc = self._main(s, ["schema", "--template", "early_warning"])
            text = s.getvalue() if isinstance(s, io.StringIO) else s.buffer.getvalue().decode("utf-8")
            self.assertEqual(rc, 0, type(s).__name__)
            self.assertIn("title", json.loads(text))
        s = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        s.write("before\n")
        rc = self._main(s, ["schema", "--template", "early_warning"])
        head, _, rest = s.buffer.getvalue().decode("utf-8").partition(os.linesep)   # the wrapper writes "\n" as os.linesep (Windows: "\r\n")
        self.assertEqual((rc, head), (0, "before"))
        self.assertIn("title", json.loads(rest))

    @unittest.skipUnless(S.NONBLOCKING_PIPE, S.NO_NONBLOCKING_PIPE)
    def test_unflushed_caller_text_on_a_full_nonblocking_pipe(self):
        """the caller's text still in its buffer, stdout a non-blocking pipe already full: that text is flushed first
        and waited for like the receipt — exit 0, "before" then the receipt, the process asleep meanwhile (at e25795e:
        exit 74 and nothing written)"""
        r, w = os.pipe()
        S.set_nonblocking(w)
        filled = 0
        while True:
            try:
                n = os.write(w, b"P" * 4096)
            except BlockingIOError:
                break
            if not n:
                break
            filled += n
        s = io.TextIOWrapper(io.BufferedWriter(io.FileIO(w, "w", closefd=False)), encoding="utf-8")
        s.write("before\n")
        got = []

        def drain():
            time.sleep(0.5)
            while True:
                b = os.read(r, 1 << 16)
                if not b:
                    break
                got.append(b)
        th = threading.Thread(target=drain)
        th.start()
        c0 = time.process_time()
        try:
            rc = self._main(s, ["schema", "--template", "early_warning"])
        finally:
            cpu = time.process_time() - c0
            os.close(w)
            th.join()
            os.close(r)
        data = b"".join(got)
        self.assertEqual(rc, 0)
        self.assertEqual(data[:filled], b"P" * filled)
        head, _, rest = data[filled:].decode("utf-8").partition("\n")
        self.assertEqual(head, "before")
        self.assertIn("title", json.loads(rest))
        self.assertLess(cpu, 0.3, "waiting must sleep, not spin")


class Encodings(unittest.TestCase):
    """the receipt's bytes are the ones Python's own stdout text layer writes for the same text — a byte order mark
    included or not as that layer decides (utf-16 / utf-32: on a file at offset 0 only, never on a pipe or after an
    append) — in six encodings and one error handler, to a new file, appended and to a pipe, buffered and unbuffered.
    The reference is a second process writing the same text with sys.stdout.write."""

    def test_text_layer_bytes(self):
        d = tempfile.mkdtemp(prefix="cra_enc_")
        self.addCleanup(shutil.rmtree, d, True)
        cli = PY + ["verify", "nö.json"]   # a receipt with a non-ASCII character
        text_path = os.path.join(d, "text")
        r = subprocess.run(cli, capture_output=True, cwd=ROOT, env=_env({"PYTHONIOENCODING": "utf-8"}), timeout=120)
        with open(text_path, "wb") as f:   # the text, not the bytes: "\n" where stdout wrote os.linesep (Windows: "\r\n")
            f.write(r.stdout.replace(os.linesep.encode(), b"\n"))
        ref = [sys.executable, "-c", "import sys; sys.stdout.write(open(sys.argv[1], encoding='utf-8', newline='').read())", text_path]

        def out_of(argv, enc, dest, env):
            e = _env(dict(env, PYTHONIOENCODING=enc))
            if dest == "pipe":
                return subprocess.run(argv, env=e, capture_output=True, cwd=ROOT, timeout=120).stdout
            o = os.path.join(d, "o")
            with open(o, "wb") as f:
                f.write(b"PRE" if dest == "append" else b"")
            with open(o, "ab" if dest == "append" else "wb") as f:
                subprocess.run(argv, env=e, stdout=f, cwd=ROOT, timeout=120)
            with open(o, "rb") as f:
                return f.read()
        for enc in ("utf-8", "utf-16", "utf-32", "utf-8-sig", "latin-1", "ascii:backslashreplace"):
            for dest in ("file", "append", "pipe"):
                for env in ({}, UNBUF):
                    a, b = out_of(cli, enc, dest, env), out_of(ref, enc, dest, env)
                    self.assertGreater(len(b), 10)
                    self.assertEqual(a, b, f"{enc} {dest} {env}")
        # the control the rule rests on: a BOM on a utf-16 file at offset 0, none on a pipe
        self.assertTrue(out_of(cli, "utf-16", "file", {}).startswith(b"\xff\xfe"))
        # on a pipe: none on POSIX; on Windows Python's own layer writes one too (measured on windows-latest, 27/11/2026)
        # — the receipt follows the layer, which the loop above checks
        self.assertEqual(out_of(cli, "utf-16", "pipe", {}).startswith(b"\xff\xfe"), S.WIN)
        self.assertEqual(out_of(ref, "utf-16", "pipe", {}).startswith(b"\xff\xfe"), S.WIN)


class PromisedFilesAndLedger(unittest.TestCase):
    """the temporary of a promised file has a name nobody can predict (created with O_EXCL): a symlink or a FIFO planted
    at `<path>.tmp` is neither followed nor waited on; a ledger line or a stored source document that cannot be written
    is 74 with nothing recorded (it was exit 1 with a traceback, the code of an overdue deadline)"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_files_")
        self.addCleanup(shutil.rmtree, self.W, True)
        self.ledger = os.path.join(self.W, "l.jsonl")
        self.args = ["--ledger", self.ledger, "--product", "p", "--version", "1"]

    def vuln(self, id_="CVE-2026-0001"):
        return subprocess.run(PY + ["vuln", *self.args, "--id", id_, "--aware", "2026-10-12T00:00:00Z", "--allow-overdue"],
                              cwd=ROOT, capture_output=True, text=True, timeout=120, env=_env())

    def test_planted_tmp_is_not_followed(self):
        self.assertEqual(self.vuln().returncode, 0)
        victim = os.path.join(self.W, "victim")
        with open(victim, "w") as f:
            f.write("untouched")
        out = os.path.join(self.W, "p.json")
        os.symlink(victim, out + ".tmp")
        fifo = os.path.join(self.W, "q.json.tmp")
        if S.WIN:   # NO_FIFO: a regular file planted there instead, which must not be opened either
            with open(fifo, "w") as f:
                f.write("planted")
        else:
            os.mkfifo(fifo)
        for target in (out, os.path.join(self.W, "q.json")):
            r = subprocess.run(PY + ["pack", *self.args, "--out", target], cwd=ROOT, capture_output=True, text=True, timeout=60, env=_env())
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(target, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["kind"], "cra_evidence_pack/1")
        with open(victim) as f:
            self.assertEqual(f.read(), "untouched")
        self.assertTrue(os.path.islink(out + ".tmp") and (S.WIN or stat.S_ISFIFO(os.lstat(fifo).st_mode)))
        left = [n for n in os.listdir(self.W) if n.endswith(".tmp")]
        self.assertEqual(sorted(left), ["p.json.tmp", "q.json.tmp"])

    def test_pack_bytes_cut(self):
        """the pack's own bytes refused part-way (file size limit): 74, no temporary left, ledger unchanged"""
        self.assertEqual(self.vuln().returncode, 0)
        with open(self.ledger, "rb") as f:
            before = f.read()
        out = os.path.join(self.W, "p.json")
        if not S.HAVE_FSIZE:
            self.skipTest(S.NO_FSIZE)
        rc, _, err = S.run(PY + ["pack", *self.args, "--out", out], "devnull", env=_env(), cwd=ROOT, fsize=1024, timeout=60)
        self.assertEqual(rc, EX_IOERR, err)
        self.assertTrue(one_line(err), err)
        self.assertEqual([n for n in os.listdir(self.W) if n.startswith("p.json")], [])
        with open(self.ledger, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_ledger_line_not_written_is_74(self):
        self.assertEqual(self.vuln().returncode, 0)
        with open(self.ledger, "rb") as f:
            before = f.read()
        if not S.HAVE_FSIZE:
            self.skipTest(S.NO_FSIZE)
        rc, out, err = S.run(PY + ["sbom", *self.args, "--installed", "pip"], "pipe", env=_env(), cwd=ROOT, fsize=1024, timeout=60)
        self.assertEqual((rc, out), (EX_IOERR, b""), err)
        self.assertTrue(one_line(err) and "nothing was recorded" in err, err)
        with open(self.ledger, "rb") as f:
            self.assertEqual(f.read(), before)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes into a read-only folder")
    def test_source_not_stored_is_74(self):
        """the copy of the ingested document cannot be stored (its folder is read-only): 74, nothing recorded"""
        src = self.ledger + ".sources"
        os.mkdir(src)
        S.deny_writes(self, src)
        p = subprocess.run(PY + ["sbom", *self.args, "--from-cyclonedx", SYFT], cwd=ROOT, capture_output=True, text=True, timeout=60, env=_env())
        self.assertEqual((p.returncode, p.stdout), (EX_IOERR, ""), p.stderr)
        self.assertTrue(one_line(p.stderr) and "nothing was recorded" in p.stderr, p.stderr)
        self.assertFalse(os.path.exists(self.ledger) and os.path.getsize(self.ledger))
        self.assertEqual(os.listdir(src), [])

    def test_source_folder_cannot_be_made_is_74(self):
        """the folder of the stored copies cannot be created (a regular file in its place): the copy cannot be stored
        either — 74, one line that says nothing was recorded, no ledger line (it was exit 1 with a traceback)"""
        with open(self.ledger + ".sources", "w") as f:
            f.write("not a folder")
        p = subprocess.run(PY + ["sbom", *self.args, "--from-cyclonedx", SYFT], cwd=ROOT, capture_output=True, text=True, timeout=60, env=_env())
        self.assertEqual((p.returncode, p.stdout), (EX_IOERR, ""), p.stderr)
        self.assertTrue(one_line(p.stderr) and "nothing was recorded" in p.stderr, p.stderr)
        self.assertFalse(os.path.exists(self.ledger) and os.path.getsize(self.ledger))

    def test_stdout_closed_leaves_the_ledger_whole(self):
        """started with fd 1 and fd 2 closed, the ledger may be opened as descriptor 1: the receipt's failure must not
        point it at /dev/null or write the receipt into it"""
        rc, _, _ = S.run(PY + ["vuln", *self.args, "--id", "CVE-2026-0001", "--aware", "2026-10-12T00:00:00Z", "--allow-overdue"],
                         "closed", "closed", env=_env(), cwd=ROOT, timeout=60)
        self.assertEqual(rc, EX_IOERR)
        self.assertEqual(self.vuln("CVE-2026-0002").returncode, 0)
        sys.path.insert(0, ROOT)
        from omega_cra_evol.ledger import Ledger
        v = Ledger(self.ledger).verify()
        self.assertTrue(v["chain_ok"])
        self.assertEqual(v["entries"], 2)


class WriteTmp(unittest.TestCase):
    """omega_cra_evol.outputs.write_tmp itself: every byte or OutputNotWritten with no temporary left, and never through a
    name that already exists (O_EXCL), even when it is the very name the call drew"""

    def setUp(self):
        self.W = tempfile.mkdtemp(prefix="cra_wt_")
        self.addCleanup(shutil.rmtree, self.W, True)

    @unittest.skipUnless(S.HAVE_FSIZE, S.NO_FSIZE)
    def test_short_write_under_a_file_size_limit(self):
        code = ("import resource, sys; sys.path.insert(0, sys.argv[1]); from omega_cra_evol import outputs\n"
                "resource.setrlimit(resource.RLIMIT_FSIZE, (100, 100))\n"
                "try:\n    outputs.write_tmp(sys.argv[2], 'x' * 1000)\nexcept outputs.OutputNotWritten as e:\n    print('refused', e)\n"
                "else:\n    print('written')\n")
        target = os.path.join(self.W, "p.json")
        r = subprocess.run([sys.executable, "-B", "-c", code, ROOT, target], capture_output=True, text=True, timeout=60, env=_env())
        self.assertTrue(r.stdout.startswith("refused"), (r.stdout, r.stderr))
        self.assertEqual(os.listdir(self.W), [])

    def test_existing_name_is_never_opened(self):
        sys.path.insert(0, ROOT)
        from omega_cra_evol import outputs
        victim = os.path.join(self.W, "victim")
        with open(victim, "w") as f:
            f.write("untouched")
        target = os.path.join(self.W, "p.json")
        os.symlink(victim, target + ".0000000000000000.tmp")
        saved = outputs.secrets.token_hex
        outputs.secrets.token_hex = lambda n: "0" * (2 * n)
        try:
            with self.assertRaises(outputs.OutputNotWritten):
                outputs.write_tmp(target, "pack")
        finally:
            outputs.secrets.token_hex = saved
        with open(victim) as f:
            self.assertEqual(f.read(), "untouched")

    def test_existing_regular_file_or_fifo_at_the_drawn_name(self):
        """O_EXCL itself, not only O_NOFOLLOW: a regular file at the very name the call drew is refused, not truncated,
        and a FIFO there is refused at once, never waited on (child process: a regression would hang, not pass)"""
        code = ("import os, sys; sys.path.insert(0, sys.argv[1]); from omega_cra_evol import outputs\n"
                "outputs.secrets.token_hex = lambda n: '0' * (2 * n)\n"
                "try:\n    outputs.write_tmp(sys.argv[2], 'pack')\nexcept outputs.OutputNotWritten as e:\n    print('refused')\n"
                "else:\n    print('written')\n")
        for kind in ("regular", "fifo"):
            with self.subTest(kind=kind):
                if kind == "fifo" and S.WIN:
                    self.skipTest(NO_FIFO)
                d = tempfile.mkdtemp(prefix="cra_wt_", dir=self.W)
                target = os.path.join(d, "p.json")
                name = target + ".0000000000000000.tmp"
                if kind == "regular":
                    with open(name, "w") as f:
                        f.write("untouched")
                else:
                    os.mkfifo(name)
                r = subprocess.run([sys.executable, "-B", "-c", code, ROOT, target], capture_output=True, text=True, timeout=30, env=_env())
                self.assertEqual(r.stdout, "refused\n", (r.stdout, r.stderr))
                if kind == "regular":
                    with open(name) as f:
                        self.assertEqual(f.read(), "untouched")
                self.assertEqual(os.listdir(d), [os.path.basename(name)])

    def test_error_at_close_is_a_failed_write(self):
        """close() inside the try: an error it reports (a deferred write error, NFS or a full disk) is OutputNotWritten
        and the temporary is removed"""
        import errno
        sys.path.insert(0, ROOT)
        from omega_cra_evol import outputs

        class FailingClose:
            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def close(fd):
                os.close(fd)
                raise OSError(errno.EIO, "Input/output error")
        saved = outputs.os
        outputs.os = FailingClose()
        try:
            with self.assertRaises(outputs.OutputNotWritten):
                outputs.write_tmp(os.path.join(self.W, "p.json"), "pack")
        finally:
            outputs.os = saved
        self.assertEqual(os.listdir(self.W), [])


FEED_REFUSAL = r"""
import sys
from omega_cra_evol import feeds
mode, ledger = sys.argv[1], sys.argv[2]
def get(url, timeout):
    if mode == "down":
        raise OSError("no network (test)")
    return {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
feeds._get_json = get
from omega_cra_evol.cli import main
sys.exit(main(["vuln", "--ledger", ledger, "--product", "p", "--version", "1", "--id", "CVE-2026-0001",
               "--aware", "2026-10-12T00:00:00Z", "--source", "cisa_kev"]))
"""


class FeedRefusalsWithStderrLost(unittest.TestCase):
    """`vuln --source cisa_kev` refused (the feed unavailable, the id not in it): one line, exit 1, nothing recorded and
    nothing on stdout — with stderr full, closed or gone too (`print(..., file=sys.stderr)` put the line on STDOUT with
    stderr closed). No network: the feed's fetch function is replaced."""

    def test_each(self):
        W = tempfile.mkdtemp(prefix="cra_feed_")
        self.addCleanup(shutil.rmtree, W, True)
        for mode, needle in (("down", "unavailable"), ("absent", "is NOT in cisa_kev")):
            with self.subTest(mode=mode):
                ledger = os.path.join(W, mode + ".jsonl")
                argv = [sys.executable, "-B", "-c", FEED_REFUSAL, mode, ledger]
                rc, out, err = run(argv, "file")
                self.assertEqual((rc, out), (1, b""), err)
                self.assertEqual(len(err.splitlines()), 1, err)
                self.assertIn(needle, err)
                for how, rc, out in stderr_lost(argv):
                    self.assertEqual((rc, out), (1, b""), how)
                self.assertFalse(os.path.exists(ledger) and os.path.getsize(ledger))


if __name__ == "__main__":
    unittest.main()

"""The sdist is complete and reproducible (15/11/2026).

Before, the sdist held the package and 49 test files but no fixtures, specifications, examples, scripts or verifiers, so
its own test suite could not run; and two builds of the same commit differed (file times in the tar, build time in the
gzip header). MANIFEST.in now names every top-level entry that git tracks, and scripts/repro_sdist.py rewrites the
sdist without build-time dates (release-build.yml runs it)."""
import gzip
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "repro_sdist.py")
PACKAGES = {"omega_cra_evol", "cra_evidence"}   # in the sdist through [tool.setuptools] packages


def make_sdist(path, mtime, extra=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        for name, data in [("p-1/", None), ("p-1/b.txt", b"bee"), ("p-1/a.py", b"print(1)\n")] + (extra or []):
            ti = tarfile.TarInfo(name.rstrip("/")); ti.mtime = mtime; ti.uname = "someone"
            if data is None:
                ti.type = tarfile.DIRTYPE; ti.mode = 0o775; t.addfile(ti)
            elif data == "symlink":
                ti.type = tarfile.SYMTYPE; ti.linkname = "a.py"; t.addfile(ti)
            else:
                ti.size = len(data); ti.mode = 0o664; t.addfile(ti, io.BytesIO(data))
    with open(path, "wb") as f, gzip.GzipFile(fileobj=f, mode="wb", mtime=mtime) as gz:
        gz.write(raw.getvalue())


def run(path, epoch="1700000000"):
    env = {"PATH": os.environ.get("PATH", ""), "SOURCE_DATE_EPOCH": epoch}
    if "SYSTEMROOT" in os.environ:   # Windows: Python 3.9 cannot seed its hash without it ("failed to get random numbers")
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return subprocess.run([sys.executable, "-I", SCRIPT, path], capture_output=True, text=True, env=env)


class TestReproSdist(unittest.TestCase):
    def test_two_builds_with_different_times_become_identical_with_the_same_files(self):
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, "a.tar.gz"), os.path.join(d, "b.tar.gz")
        make_sdist(a, 1_600_000_000); make_sdist(b, int(time.time()))
        self.assertNotEqual(open(a, "rb").read(), open(b, "rb").read())   # positive control: they differ before
        for p in (a, b):
            self.assertEqual(run(p).returncode, 0)
        self.assertEqual(open(a, "rb").read(), open(b, "rb").read())
        with tarfile.open(a) as t:
            self.assertEqual([m.name for m in t.getmembers()], ["p-1", "p-1/a.py", "p-1/b.txt"])
            self.assertEqual(t.extractfile("p-1/b.txt").read(), b"bee")
            self.assertEqual({m.mtime for m in t.getmembers()}, {1700000000})
            self.assertEqual({(m.uname, m.uid) for m in t.getmembers()}, {("", 0)})

    def test_a_link_is_refused_and_the_file_is_left_as_it_was(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "s.tar.gz")
        make_sdist(p, 1_600_000_000, [("p-1/link", "symlink")]); before = open(p, "rb").read()
        r = run(p)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("only regular files and directories", r.stderr)
        self.assertEqual(open(p, "rb").read(), before)

    def test_without_a_valid_epoch_it_refuses(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "s.tar.gz"); make_sdist(p, 1)
        for bad in ("", "x", "-5", "1.5"):
            self.assertEqual(run(p, bad).returncode, 2, bad)


@unittest.skipUnless(os.path.isdir(os.path.join(ROOT, ".git")) or os.path.isfile(os.path.join(ROOT, ".git")),
                     "not a git checkout (e.g. the unpacked sdist): nothing to compare MANIFEST.in with")
class TestManifest(unittest.TestCase):
    def test_every_tracked_top_level_entry_is_in_the_sdist(self):
        files = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, check=True).stdout.split()
        top = {f.split("/")[0] for f in files}
        rules = [l.split() for l in open(os.path.join(ROOT, "MANIFEST.in"), encoding="utf-8")
                 if l.strip() and not l.startswith("#")]
        named = {w for r in rules if r[0] in ("include", "graft") for w in r[1:]}
        default = {"pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"}   # setuptools adds these itself
        missing = sorted(t for t in top if t not in named and t not in PACKAGES and t not in default)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()

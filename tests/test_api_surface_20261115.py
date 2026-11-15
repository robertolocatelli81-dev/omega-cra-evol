# SPDX-License-Identifier: AGPL-3.0-or-later
"""15/11/2026 — the declared API (API.md). Every module has a literal, sorted `__all__`; the package's own `__all__`
is the stable tier, twelve names; the interface (each name in an `__all__`, with its signature) equals the versioned
file tests/data/api_surface.txt, so that a change of the API is a line of diff someone approves, never a side effect;
no public signature lacks an annotation, and the private ones that do can only decrease. Read with `ast`
(scripts/api_surface.py): nothing is imported, no type checker is needed. Each check has a positive control on a
broken copy. What this does NOT check: that an annotation is right — that is the `types` job (mypy --strict)."""
import os, shutil, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import api_surface  # noqa: E402

PKG = os.path.join(ROOT, "omega_cra_evol")
SNAPSHOT = os.path.join(ROOT, "tests", "data", "api_surface.txt")
STABLE = ["DryRunDrop", "EvidenceLocker", "SBOMComponent", "SBOMRecord", "SRPNotice", "VulnerabilityRecord", "__version__",
          "sbom_from_cyclonedx", "sbom_from_installed", "sbom_from_spdx", "srp_schema", "verify_pack"]
PRIVATE_HOLES_CEILING = 25     # measured 15/11/2026; lower it when a private signature is annotated, never raise it
TYPE_IGNORE_CEILING = 1        # measured 15/11/2026 (sbom.py, the optional `packaging` import)


def broken_copy(edit):
    """a copy of the package in a temporary folder, with `edit(path of the copy)` applied"""
    d = tempfile.mkdtemp()
    dst = os.path.join(d, "omega_cra_evol")
    shutil.copytree(PKG, dst, ignore=shutil.ignore_patterns("__pycache__", "data"))
    edit(dst)
    return d, dst


def rewrite(path, old, new):
    with open(path, encoding="utf-8") as f:
        s = f.read()
    assert s.count(old) == 1, (path, old, s.count(old))
    with open(path, "w", encoding="utf-8") as f:
        f.write(s.replace(old, new))


class TestDeclaredInterface(unittest.TestCase):
    def test_every_module_has_a_literal_sorted_all(self):
        self.assertEqual(api_surface.all_problems(PKG), [])

    def test_positive_control_a_wrong_all_is_reported(self):
        out = lambda p: os.path.join(p, "outputs.py")   # noqa: E731
        cases = [
            (lambda p: rewrite(out(p), '"write_file", "write_tmp",', '"write_file", "write_tmp", "no_such_name",'), "neither defines nor imports"),
            (lambda p: rewrite(out(p), '"OutputNotWritten", "TipNotWritten",', '"TipNotWritten", "OutputNotWritten",'), "not sorted"),
            (lambda p: rewrite(out(p), '__all__ = [\n    "OutputNotWritten"', '__all__ = [n for n in ()] or [\n    "OutputNotWritten"'), "no literal __all__"),
            (lambda p: rewrite(out(p), '"OutputNotWritten",', '"OutputNotWritten", "OutputNotWritten",'), "duplicate"),
            (lambda p: rewrite(out(p), '"OutputNotWritten",', '"OutputNotWritten", "_x",'), "private"),
        ]
        for edit, expected in cases:
            d, dst = broken_copy(edit)
            try:
                problems = api_surface.all_problems(dst)
                self.assertTrue(any(expected in p for p in problems), (expected, problems))
            finally:
                shutil.rmtree(d)

    def test_the_stable_tier_is_these_twelve_names(self):
        self.assertEqual(api_surface.literal_all(api_surface.parse(os.path.join(PKG, "__init__.py"))), STABLE)
        import omega_cra_evol
        self.assertEqual(omega_cra_evol.__all__, STABLE)
        for n in STABLE:
            getattr(omega_cra_evol, n)

    def test_every_listed_name_exists_at_runtime(self):
        import importlib
        for name, _ in api_surface.modules(PKG):
            if name == "__init__":
                continue
            mod = importlib.import_module("omega_cra_evol." + name)
            for n in mod.__all__:
                self.assertTrue(hasattr(mod, n), f"{name}.{n}")

    def test_the_interface_is_the_versioned_snapshot(self):
        with open(SNAPSHOT, encoding="utf-8") as f:
            want = f.read()
        got = api_surface.snapshot(PKG)
        if got != want:
            import difflib
            diff = "".join(difflib.unified_diff(want.splitlines(True), got.splitlines(True), "tests/data/api_surface.txt", "the code", n=0))
            self.fail("the API changed. If it is meant (API.md says what each tier allows), regenerate the snapshot with\n"
                      "  python3 scripts/api_surface.py snapshot omega_cra_evol > tests/data/api_surface.txt\n"
                      "and name the change in CHANGELOG.md:\n" + diff)

    def test_positive_control_a_changed_signature_changes_the_snapshot(self):
        with open(SNAPSHOT, encoding="utf-8") as f:
            want = f.read()
        edits = [
            lambda p: rewrite(os.path.join(p, "verify_pack.py"), "def verify_pack(path: str,", "def verify_pack(pack_path: str,"),     # a renamed parameter
            lambda p: rewrite(os.path.join(p, "outputs.py"), '"write_file", "write_tmp",', '"write_file",'),                             # a name withdrawn
            lambda p: rewrite(os.path.join(p, "applicability.py"), "def local_date(at: datetime, reading: str) -> date:", "def local_date(at: datetime, reading: str) -> datetime:"),
        ]
        for edit in edits:
            d, dst = broken_copy(edit)
            try:
                self.assertNotEqual(api_surface.snapshot(dst), want)
            finally:
                shutil.rmtree(d)
        d, dst = broken_copy(lambda p: None)                                    # and the untouched copy gives the same text
        try:
            self.assertEqual(api_surface.snapshot(dst), want)
        finally:
            shutil.rmtree(d)


class TestAnnotations(unittest.TestCase):
    def test_no_public_signature_lacks_an_annotation_and_the_private_ones_only_decrease(self):
        total = api_surface.measure(PKG)["total"]
        self.assertEqual(total["holes_public"], 0)
        self.assertLessEqual(total["holes_private"], PRIVATE_HOLES_CEILING)
        self.assertLessEqual(total["type_ignore_comments"], TYPE_IGNORE_CEILING)

    def test_positive_control_a_public_signature_without_annotation_is_counted(self):
        d, dst = broken_copy(lambda p: rewrite(os.path.join(p, "ledger.py"), "def open_regular(path: str) -> BinaryIO:", "def open_regular(path):"))
        try:
            self.assertEqual(api_surface.measure(dst)["total"]["holes_public"], 1)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()

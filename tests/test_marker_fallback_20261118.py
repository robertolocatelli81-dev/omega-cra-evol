# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/SBOM_INGEST.md, "Not an ingest: PEP 508 markers of the installed floor", written before the code.

Without `packaging`, 0.12.0's fallback split the marker text on " and " / " or " before reading its strings, and
compared versions as tuples. Measured that day: `os_name == 'posix and linux'`, `os_name == 'nt or posix'`,
`platform_release == 'a(b)'` were None (packaging: False); `python_version == '<this>.0'` and `python_version == '3.*'`
were False (packaging: True — a dependency of this interpreter left out of the SBOM); `os_name ~= 'posix'` was True
(packaging: undefined). With `packaging`, `UndefinedComparison` was not caught (a traceback).

Generative differential test against `packaging.markers` (skipped where it is not importable; the hand-written cases
run everywhere): random markers over the ten variables, every operator, string constants that contain `and`, `or`,
parentheses and the other quote, plain / wildcard / pre-release / non-version constants, nested parentheses. Rule:
where the fallback answers a boolean it is packaging's; on the defined subset (spec: string fields with any operator
but `~=` / `===`, version fields with plain releases) it answers a boolean. Positive control: the same test against the
fallback of 0.12.0 (4557a1f) finds disagreements (measured, CHANGELOG 0.13.0)."""
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import sbom as S  # noqa: E402

try:
    from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName
    HAVE_PACKAGING = True
except ImportError:
    HAVE_PACKAGING = False

ENV = S._marker_env()
PV = ENV["python_version"]
STRING_FIELDS = ("os_name", "sys_platform", "platform_system", "platform_version", "platform_machine",
                 "platform_python_implementation", "implementation_name")
VERSION_FIELDS = ("python_version", "python_full_version")
OPS = ("==", "!=", "<", "<=", ">", ">=", "~=", "===", "in", "not in")


def fallback(m):
    return S._fallback_marker(m.strip()) if m.strip() else True


def reference(m):
    try:
        return bool(Marker(m).evaluate(environment=dict(ENV)))
    except (InvalidMarker, UndefinedEnvironmentName, UndefinedComparison):
        return None


class HandWritten(unittest.TestCase):
    """the cases of the review and of the spec; their packaging answers measured on 18/11/2026 (packaging 26.3)"""

    def test_strings_with_operators_inside(self):
        o = ENV["os_name"]
        self.assertIs(fallback(f"os_name == '{o} and linux'"), False)
        self.assertIs(fallback(f"os_name == 'nt or {o}'"), False)
        self.assertIs(fallback("platform_release == 'a(b)'"), False)
        self.assertIs(fallback(f'os_name == "{o}" and (os_name == "nt" or os_name == "{o}")'), True)
        self.assertIs(fallback(f"os_name == \"it's\" or os_name == '{o}'"), True)
        self.assertIs(fallback(f"os_name=='{o}'and os_name!='x'"), True)
        self.assertIs(fallback(f"((os_name == '{o}'))"), True)

    def test_versions_as_pep_440(self):
        self.assertIs(fallback(f"python_version == '{PV}.0'"), True)
        self.assertIs(fallback(f"python_version == '{PV.split('.')[0]}.*'"), True)
        self.assertIs(fallback(f"python_version != '{PV.split('.')[0]}.*'"), False)
        self.assertIs(fallback(f"python_version ~= '{PV}'"), True)
        self.assertIsNone(fallback("python_version ~= '3'"))
        self.assertIs(fallback(f"python_version >= '{PV}'"), True)
        self.assertIs(fallback(f"python_version < '{PV}'"), False)
        self.assertIs(fallback(f"'{PV}' in python_version"), True)

    def test_none_where_documented(self):
        for m in ("os_name ~= 'posix'", "os_name === 'posix'", "extra == 'x'", "implementation_version >= '3'",
                  "'a' == 'a'", "os_name == sys_platform", "os_name == 'posix' and", "os_name", "os_name == posix",
                  "(os_name == 'posix'", "os.name == 'posix'", f"python_version >= '{PV}rc1'",
                  f"python_version == '{PV}' or extra == 'x'"):
            self.assertIsNone(fallback(m), m)

    def test_answer_is_bool_or_none(self):
        for m in ("", "os_name == 'posix'", "garbage ((", "os_name == 'x' or"):
            self.assertIn(S.marker_applies(m), (True, False, None), m)

    @unittest.skipUnless(HAVE_PACKAGING, "needs packaging")
    def test_undefined_comparison_is_none_not_a_traceback(self):
        self.assertIsNone(S.marker_applies("os_name ~= 'posix'"))
        self.assertIsNone(S.marker_applies("os_name === 'posix'"))


def _const(rnd, field):
    pool = ["posix", "nt", "linux", "Linux", "x86_64", "CPython", "cpython", "darwin", "win32", "",
            "posix and linux", "nt or posix", "a(b)", "(", ")", "it's", 'say "hi"', "and", "or", "not in",
            ENV.get(field, "x"), ENV.get(field, "x")[:3] if ENV.get(field) else "x"]
    if field in VERSION_FIELDS:
        major, minor = PV.split(".")[:2]
        pool += [PV, PV + ".0", f"{major}.*", f"{major}.{minor}.*", f"{major}.{int(minor) - 1}", f"{major}.{int(minor) + 1}",
                 "3", "4.0", ENV["python_full_version"], PV + "rc1", "1!3.0", PV + ".post1", PV + "+local", "abc",
                 " " + PV, "3.x"]
    c = rnd.choice(pool)
    q = "'" if "'" not in c else '"'
    if q in c:
        return "'x'"
    return q + c + q


def _atom(rnd):
    field = rnd.choice(STRING_FIELDS + VERSION_FIELDS + ("platform_release",))
    op = rnd.choice(OPS)
    c = _const(rnd, field)
    ws = rnd.choice(["", " ", "  "])
    left, right = (field, c) if rnd.random() < 0.8 else (c, field)
    sep = f" {op} " if op in ("in", "not in") else f"{ws}{op}{ws}"
    return f"{left}{sep}{right}"


def _marker(rnd, depth=0):
    if depth > 2 or rnd.random() < 0.45:
        a = _atom(rnd)
        return f"({a})" if rnd.random() < 0.15 else a
    j = rnd.choice([" and ", " or ", " and ", " or "])
    return f"({_marker(rnd, depth + 1)}){j}{_marker(rnd, depth + 1)}" if rnd.random() < 0.3 else \
        f"{_marker(rnd, depth + 1)}{j}{_marker(rnd, depth + 1)}"


def _defined(atom_field, op, const):
    """the spec's subset where the fallback must answer a boolean"""
    if op in ("in", "not in"):
        return True
    if atom_field in STRING_FIELDS:
        return op not in ("~=", "===")
    return False


@unittest.skipUnless(HAVE_PACKAGING, "the differential oracle is packaging.markers")
class Differential(unittest.TestCase):
    def test_generative_against_packaging(self):
        rnd = random.Random(20261118)
        n = agree_bool = 0
        wrong, none_on_defined = [], []
        for _ in range(6000):
            m = _marker(rnd)
            want, got = reference(m), fallback(m)
            n += 1
            if got is not None:
                if got != want:
                    wrong.append((m, want, got))
                else:
                    agree_bool += 1
        for _ in range(3000):                       # single atoms of the defined subset: a boolean is required
            field = rnd.choice(STRING_FIELDS)
            op = rnd.choice([o for o in OPS if o not in ("~=", "===")])
            m = f"{field} {op} {_const(rnd, field)}"
            want, got = reference(m), fallback(m)
            if got is None and want is not None and _defined(field, op, None):
                none_on_defined.append(m)
            elif got is not None and got != want:
                wrong.append((m, want, got))
        rnd2 = random.Random(7)
        major, minor = (int(x) for x in PV.split(".")[:2])
        for _ in range(3000):                       # version fields, plain releases: a boolean is required
            field = rnd2.choice(VERSION_FIELDS)
            op = rnd2.choice(("==", "!=", "<", "<=", ">", ">=", "~=", "==*", "!=*"))
            parts = [str(major), str(minor + rnd2.choice((-1, 0, 0, 1)))][:rnd2.choice((1, 2, 2))]
            parts += [str(rnd2.choice((0, 0, 1, 25)))] * rnd2.choice((0, 0, 1, 2))
            v = ".".join(parts)
            if op.endswith("*"):
                op, v = op[:-1], v + ".*"
            m = f"{field} {op} '{v}'"
            want, got = reference(m), fallback(m)
            if got is None and want is not None and not (op == "~=" and len(parts) < 2):
                none_on_defined.append(m)
            elif got is not None and got != want:
                wrong.append((m, want, got))
        self.assertEqual(wrong, [], f"{len(wrong)} opposite answers")
        self.assertEqual(none_on_defined, [], f"{len(none_on_defined)} None on the defined subset")
        self.assertGreater(agree_bool, 1500)
        print(f"  {n} random markers: {agree_bool} answered as packaging, {n - agree_bool} None")


if __name__ == "__main__":
    unittest.main()

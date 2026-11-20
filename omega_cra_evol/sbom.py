# SPDX-License-Identifier: AGPL-3.0-or-later
"""SBOM records for CRA Annex I Part II point 1 ("software bill of materials in a commonly used and machine-readable
format covering at the very least the top-level dependencies").

Two honest ways in: (a) `sbom_from_installed` — this Python environment via importlib.metadata (top-level or
transitive), a floor, not a scanner; (b) `sbom_from_cyclonedx` — ingest a CycloneDX JSON produced by a best-in-class
generator (Syft, Trivy, cdxgen…) or `sbom_from_spdx`: the 2026 verdict of the competitor comparison is to
interoperate with the leaders and add what they lack — tamper-evident, offline-verifiable evidence with Art. 14
deadlines. The record is a normalised INDEX of the generator's document (name/version/type/purl/cpe/sha256/licence,
flattened, de-duplicated); the generator's document itself is the evidence: its exact bytes (SHA-256) are bound
into the record and the locker stores them next to the ledger (measured 20/09/2026 with sbomqs 2.1.2: 0.2.0's export,
which was only the index, scored lower than every generator's original — 5.3→4.2 Syft, 6.6→4.4 cdxgen, 4.8→3.7
Trivy — so since 0.3.0 the original is kept, not replaced; the enriched 0.3.0 index scores 5.3 / 5.5 / 4.8). Export is a CycloneDX 1.6 or 1.7 SUBSET (bomFormat,
specVersion, serialNumber, metadata with tools/component, components with bom-ref/type/purl/cpe/hashes/licenses,
dependencies only where they are known), declared as such and validated against the official schemas in the tests.
"""
from __future__ import annotations

# The names other code may import from this module (provisional tier of API.md: typed, may change in a minor
# release with a changelog note). Everything else here is private. tests/test_api_surface.py keeps the list.
__all__ = [
    "CYCLONEDX_COMPONENT_TYPES", "CYCLONEDX_EXPORT_VERSIONS", "ECMA_KEYWORDS", "EcmaPatternUnsupported",
    "INGESTED_FORMATS", "IRI_REFERENCE", "MAX_SOURCE_BYTES", "PURL_TYPE_TO_OSV", "SBOMComponent", "SBOMRecord",
    "SCHEMA_TEXT_MAX", "SPDX3_CONTEXT_301", "SPDX_PURPOSE_TO_TYPE", "components_for_osv",
    "cyclonedx_schema_check", "dedup", "ecma_pattern", "installed_license", "is_ci_component", "is_iri_reference",
    "is_spdx_expression", "is_spdx_id", "is_version_range", "marker_applies", "pypi_purl", "reingest", "resolved_components",
    "sbom_from_cyclonedx", "sbom_from_installed", "sbom_from_spdx", "schema_patterns", "source_fingerprint",
    "spdx_schema_check",
]

import copy
import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .canonical import sha3_hex


@dataclass(frozen=True)
class SBOMComponent:
    name: str
    version: str
    supplier: str = ""
    purl: str = ""
    sha256: str = ""
    license: str = ""
    type: str = "library"      # CycloneDX component type as declared by the generator (library, application, file, …)
    cpe: str = ""


def dedup(components: List[SBOMComponent]) -> List[SBOMComponent]:
    seen, out = set(), []
    for c in components:
        k = (c.name, c.version, c.purl)
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


@dataclass(frozen=True)
class SBOMRecord:
    product_id: str
    product_version: str
    components: List[SBOMComponent]
    depth: str = "top-level-only"       # "transitive" | "external:cyclonedx:<generator>"
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    # the generator's document, as measured at ingest: format, generator+version, spec version, what it declared
    # (component count incl. nested, dependency edges, component types) and what the index did to it (merged
    # duplicates) — and, when `source_fingerprint()` was applied, the SHA-256 of its exact bytes
    source: Dict[str, Any] = field(default_factory=dict)
    product_type: str = "application"   # CycloneDX type of metadata.component (application, library, firmware, device…)
    # dependency edges KNOWN to the producer, as [parent_key, child_key] over `name.lower()` ("" = the product): the
    # installed floor fills them from importlib.metadata `Requires-Dist`; an ingested document leaves them empty (its
    # graph lives in the stored source and is never re-invented)
    edges: List[List[str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        # deterministic order: the same environment must give the same SBOM bytes whatever the traversal order
        object.__setattr__(self, "components", sorted(dedup(self.components), key=lambda c: (c.name.lower(), c.version, c.purl)))

    def canonical_hash(self) -> str:
        return sha3_hex(asdict(self))

    def to_cyclonedx_min(self, spec_version: str = "1.6") -> Dict[str, Any]:
        """CycloneDX 1.6 or 1.7 JSON (root has additionalProperties:false; our extras live in metadata.properties).
        bom-ref = purl when the generator gave one, else name@version, made unique; `dependencies` are emitted only
        from `edges` the producer KNOWS (the installed floor: top-level = direct dependencies of the product,
        transitive = the Requires-Dist graph as walked) — for an ingested document the graph is the generator's and
        lives in the stored source, it is never re-invented."""
        if spec_version not in CYCLONEDX_EXPORT_VERSIONS:
            raise ValueError(f"spec_version must be one of {sorted(CYCLONEDX_EXPORT_VERSIONS)}")
        if len(self.product_version) > SCHEMA_TEXT_MAX:
            raise ValueError(f"product_version longer than {SCHEMA_TEXT_MAX} characters cannot be exported as CycloneDX (schema maxLength)")
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", self.record_id):
            raise ValueError("record_id must be a UUID (it becomes the CycloneDX serialNumber urn:uuid:…)")
        from . import __version__
        # a declared-but-NOT-INSTALLED dependency is not a component of the product: it is NAMED in a property, never
        # listed as a component with a fabricated version (resolved_components() already excludes it from the floor)
        installed_floor = self.source.get("format") == "installed"   # the sentinel is ours: an ingested document's literal "NOT-INSTALLED" is just a version string
        not_installed = [c.name for c in dedup(self.components) if installed_floor and c.version == "NOT-INSTALLED"]
        comps = [c for c in dedup(self.components) if not (installed_floor and c.version == "NOT-INSTALLED")]
        refs, used = [], set()
        for c in comps:
            ref = c.purl or f"{c.name}@{c.version}"
            base, n = ref, 1
            while ref in used:
                n += 1
                ref = f"{base}#{n}"
            used.add(ref)
            refs.append(ref)
        primary_ref = f"{self.product_id}@{self.product_version}"
        while primary_ref in used:
            primary_ref += "#product"
        out = {"bomFormat": "CycloneDX", "specVersion": spec_version, "serialNumber": f"urn:uuid:{self.record_id}", "version": 1,
               "metadata": {"timestamp": self.generated_utc,
                            "tools": {"components": [{"type": "application", "name": "omega-cra-evol", "version": __version__}]},
                            "component": {"type": self.product_type if self.product_type in CYCLONEDX_COMPONENT_TYPES else "application",
                                          "bom-ref": primary_ref, "name": self.product_id, "version": self.product_version},
                            "properties": [
                                {"name": "cra-evidence:profile", "value": f"cra-evidence-min (depth: {self.depth})"},
                                {"name": "cra-evidence:depth_note", "value": "'top-level-only' is the literal Annex I floor; most vulnerabilities live in transitive dependencies — prefer a transitive SBOM from a full generator when available"},
                                {"name": "cra-evidence:sbom_sha3", "value": self.canonical_hash()}]},
               "components": [{"type": c.type if c.type in CYCLONEDX_COMPONENT_TYPES else "library", "bom-ref": ref, "name": c.name,
                               **({"version": c.version} if c.version and c.version != "NOASSERTION" else {}),   # no version declared / an SPDX token: omitted (optional since 1.4)
                               **({"supplier": {"name": c.supplier}} if c.supplier else {}),
                               **({"purl": c.purl} if c.purl else {}),
                               **({"cpe": c.cpe} if c.cpe else {}),
                               **({"hashes": [{"alg": "SHA-256", "content": c.sha256}]} if c.sha256 else {}),
                               **(_license_entry(c.license) if c.license else {})}
                              for c, ref in zip(comps, refs)]}
        if self.source.get("sha256"):
            out["metadata"]["properties"].append({"name": "cra-evidence:source_sha256", "value": self.source["sha256"]})
        if not_installed:
            out["metadata"]["properties"].append({"name": "cra-evidence:declared_not_installed", "value": ", ".join(not_installed)})
        if self.source.get("root_purpose_declared") and SPDX_PURPOSE_TO_TYPE.get(self.source["root_purpose_declared"]) is None:
            out["metadata"]["properties"].append({"name": "cra-evidence:root_purpose_declared", "value": self.source["root_purpose_declared"]})   # the default type above is then declared as such
        if self.edges:
            # `dependsOn: []` is the POSITIVE statement "has no dependencies" (CycloneDX dependency definition): it is
            # emitted only for a component whose Requires-Dist was actually read AND whose every declared child is
            # exportable; a parent with a child that is not a component (declared but NOT-INSTALLED) has an
            # incomplete list, so it is left out of the graph and declared `unknown` with the non-walked ones
            ref_of = {_norm_key(c.name): r for c, r in zip(comps, refs)}
            ref_of[""] = primary_ref
            deps: Dict[str, List[str]] = {primary_ref: []}
            for key in self.source.get("requires_dist_read", []):
                if key in ref_of:
                    deps.setdefault(ref_of[key], [])
            incomplete = set()
            for parent, child in self.edges:
                pr, cr = ref_of.get(parent), ref_of.get(child)
                if pr is None or pr not in deps:
                    continue
                if cr is None:                  # the child was declared but is not a component of the product
                    incomplete.add(pr)
                    continue
                if cr not in deps[pr]:
                    deps[pr].append(cr)
            for r in incomplete:
                deps.pop(r, None)
            if deps:
                out["dependencies"] = [{"ref": r, "dependsOn": d} for r, d in deps.items()]
            unknown = [r for r in [primary_ref] + refs if r not in deps]
            if unknown:   # "unknown": completeness inconclusive (CycloneDX enum) — "incomplete" would assert that more exist
                out["compositions"] = [{"aggregate": "unknown", "dependencies": unknown}]
        return out


def _license_entry(lic: str) -> Dict[str, Any]:
    if is_spdx_expression(lic):
        return {"licenses": [{"expression": lic}]}
    return {"licenses": [{"license": ({"id": lic} if is_spdx_id(lic) else {"name": lic})}]}


CYCLONEDX_EXPORT_VERSIONS = {"1.6", "1.7"}
INGESTED_FORMATS = frozenset({"cyclonedx-json", "spdx-json", "spdx-jsonld"})   # source.format of a generator document: floor only when "conformant to"
MAX_SOURCE_BYTES = 256 << 20   # a generator document above this is refused unread, at ingest and by every verifier
CYCLONEDX_COMPONENT_TYPES = {"application", "framework", "library", "container", "platform", "operating-system", "device",
                             "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"}


def source_fingerprint(path: str) -> Dict[str, Any]:
    """The exact bytes of the generator's document: SHA-256, size, file name. What the locker stores and what every
    verifier re-hashes; independent of any JSON re-serialisation (a float, a key order or an escape never changes it)."""
    from .ledger import read_regular       # a regular file within the bound (a FIFO or a device is refused unread)
    raw = read_regular(path, MAX_SOURCE_BYTES)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw), "file": os.path.basename(path)}


_EXTRA_MARKER = re.compile(r"""extra\s*==\s*['"]""")


def _is_extra_requirement(req: str) -> bool:
    """PEP 508 marker `extra == "x"` in any spacing/quoting: an optional dependency, not part of the runtime SBOM."""
    return bool(_EXTRA_MARKER.search(req))


_SPDX_IDS: Optional[set] = None


def is_spdx_id(value: str) -> bool:
    """True only for an identifier in the SPDX license list vendored with the package (CycloneDX `license.id` is an
    enum of those); anything else is exported as `license.name` (free text), which the schema allows."""
    global _SPDX_IDS
    if _SPDX_IDS is None:
        try:
            p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "spdx.schema.json")
            with open(p, encoding="utf-8") as f:
                _SPDX_IDS = set(json.load(f).get("enum", []))
        except (OSError, ValueError):
            _SPDX_IDS = set()
    return value in _SPDX_IDS


_VERSION_RANGE = re.compile(r"[<>=,|^*\s]|\A~")   # spec/SBOM_INGEST.md, "The floor counts versions" (0.13.0)


def is_version_range(version: str) -> bool:
    """A range or a constraint (`>= 2.5,< 4`, `^1.2`, `~1.2`, `1.*`), not a version: `<`, `>`, `=`, `,`, `|`, `^`, `*`
    or white space anywhere, or `~` first. `5.7-0.5~deb12u1` (Debian), `1.0+build`, `1:2.3` are versions."""
    return bool(_VERSION_RANGE.search(version))


def is_ci_component(c: SBOMComponent) -> bool:
    """A CI workflow step (purl `pkg:githubactions/…`): not a component of the product (Annex I part II(1))."""
    return c.purl.lower().startswith("pkg:githubactions/")


def resolved_components(record: "SBOMRecord") -> List[SBOMComponent]:
    """Components with a real version (a declared-but-NOT-INSTALLED dependency is not evidence of anything); from 0.13.0
    a version range and a CI action are not counted either (spec/SBOM_INGEST.md, "The floor counts versions")."""
    return [c for c in record.components if c.version and c.version not in ("NOT-INSTALLED", "NOASSERTION", "NONE")
            and not is_version_range(c.version) and not is_ci_component(c)]


def _floor_counts(comps: List[SBOMComponent]) -> Dict[str, int]:
    """source.versions_not_resolved / source.ci_components of an ingested document (spec/SBOM_INGEST.md, 0.13.0)"""
    u = dedup(comps)
    return {"versions_not_resolved": sum(1 for c in u if c.version and not is_ci_component(c) and is_version_range(c.version)),
            "ci_components": sum(1 for c in u if is_ci_component(c))}


def pypi_purl(name: str, version: str) -> str:
    """purl for PyPI per the purl spec: name lowercased, runs of [-_.] → '-' (PEP 503 normalisation)."""
    return f"pkg:pypi/{re.sub(r'[-_.]+', '-', name.lower())}@{version}"


PURL_TYPE_TO_OSV = {"pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "maven": "Maven", "golang": "Go", "nuget": "NuGet",
                    "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "cocoapods": "CocoaPods"}


def components_for_osv(record: "SBOMRecord") -> List[Dict[str, str]]:
    """Map an (ingested) SBOM's purls to OSV ecosystems so a Syft/Trivy SBOM of any ecosystem can be queried;
    components without a mappable purl are returned with ecosystem "" (the caller sees what was NOT queried)."""
    out = []
    for c in record.components:
        eco = ""
        if c.purl.startswith("pkg:"):
            typ = c.purl[4:].split("/", 1)[0].split("?")[0]
            eco = PURL_TYPE_TO_OSV.get(typ, "")
        out.append({"name": c.name, "version": c.version, "ecosystem": eco})
    return out


_MARKER_ENV = None


def _marker_env() -> Dict[str, str]:
    """PEP 508 environment markers of THIS interpreter (the variables generators evaluate: python_version,
    python_full_version, platform_python_implementation, implementation_name, sys_platform, platform_system,
    platform_machine, os_name)."""
    global _MARKER_ENV
    if _MARKER_ENV is None:
        import platform
        v = sys.version_info
        _MARKER_ENV = {"python_version": f"{v.major}.{v.minor}", "python_full_version": platform.python_version(),
                       "platform_python_implementation": platform.python_implementation(), "implementation_name": sys.implementation.name,
                       "sys_platform": sys.platform, "platform_system": platform.system(), "platform_machine": platform.machine(),
                       "os_name": os.name, "platform_release": platform.release(), "platform_version": platform.version()}
    return _MARKER_ENV


# spec/SBOM_INGEST.md, "PEP 508 markers of the installed floor" (0.13.0, 18/11/2026): the fallback used when `packaging` is
# not importable parses the grammar of the PyPA "Dependency specifiers" and answers packaging's boolean, or None.
_VERSION_FIELDS = frozenset(("python_version", "python_full_version", "platform_release"))   # packaging's, minus the
_PLAIN = re.compile(r"[0-9]+(?:\.[0-9]+)*")                                                     # one this env lacks
_NOT_A_VERSION_CHAR = re.compile(r"[^A-Za-z0-9._+!*\-\s]")
_MARKER_TOKEN = re.compile(r"""\s*(?:(?P<str>'[^']*'|"[^"]*")|(?P<op>===|==|!=|<=|>=|~=|<|>)|(?P<par>[()])"""
                           r"""|(?P<word>[A-Za-z_][A-Za-z0-9_.]*))""")


def _release(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _padded(a: Tuple[int, ...], b: Tuple[int, ...]) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _string_op(op: str, left: str, right: str) -> Optional[bool]:
    """a string field (and packaging's fallback when the specifier is invalid): Python strings, case-sensitive; `<` and
    `>` false, `<=` and `>=` as `==` (Dependency specifiers, January 2026); `~=`, `===` undefined"""
    if op in ("==", "<=", ">="):
        return left == right
    if op == "!=":
        return left != right
    if op in ("<", ">"):
        return False
    return None


def _version_op(op: str, left: str, right: str) -> Optional[bool]:
    """a version field: packaging builds Specifier(op + right) and asks whether it contains `left`"""
    lv, rv = left.strip(), right.strip()
    wild = op in ("==", "!=") and rv.endswith(".*") and _PLAIN.fullmatch(rv[:-2]) is not None
    if _PLAIN.fullmatch(lv) and (wild or _PLAIN.fullmatch(rv)):
        if op == "===":
            return lv == rv
        a = _release(lv)
        if wild:
            prefix = _release(rv[:-2])
            hit = (a + (0,) * len(prefix))[:len(prefix)] == prefix
            return hit if op == "==" else not hit
        b = _release(rv)
        if op == "~=":
            if len(b) < 2:
                return None
            x, y = _padded(a, b)
            return x >= y and (a + (0,) * len(b))[:len(b) - 1] == b[:-1]
        x, y = _padded(a, b)
        return {"==": x == y, "!=": x != y, "<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]
    if not any(c.isdigit() for c in right) or _NOT_A_VERSION_CHAR.search(right):
        return _string_op(op, left, right)   # the right value cannot be a version: packaging's invalid specifier
    return None


def _marker_tokens(marker: str) -> Optional[List[Tuple[str, str]]]:
    out: List[Tuple[str, str]] = []
    i = 0
    while i < len(marker):
        if marker[i:].strip() == "":
            break
        m = _MARKER_TOKEN.match(marker, i)
        if not m:
            return None
        kind = m.lastgroup or ""
        val = m.group(kind)
        if kind == "word" and val in ("and", "or", "in", "not"):
            kind = val
        out.append((kind, val))
        i = m.end()
    return out


def _fallback_marker(marker: str) -> Optional[bool]:
    """the grammar of Dependency specifiers: marker_or := marker_and ('or' marker_and)*; marker_and := marker_expr
    ('and' marker_expr)*; marker_expr := marker_var marker_op marker_var | '(' marker_or ')'. None: outside the
    grammar, an unknown variable, two variables or two strings compared, or an undefined comparison."""
    toks = _marker_tokens(marker)
    if not toks:
        return None
    env = _marker_env()
    pos = 0
    unknown = False

    def peek(k=0):
        return toks[pos + k] if pos + k < len(toks) else ("end", "")

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def expr():
        nonlocal unknown
        if peek()[0] == "par" and peek()[1] == "(":
            take()
            v = disj()
            if peek() != ("par", ")"):
                raise ValueError("')' expected")
            take()
            return v
        a = take()
        if peek()[0] == "op":
            op = take()[1]
        elif peek()[0] == "in":
            take()
            op = "in"
        elif peek()[0] == "not" and peek(1)[0] == "in":
            take(); take()
            op = "not in"
        else:
            raise ValueError("operator expected")
        b = take()
        if a[0] not in ("str", "word") or b[0] not in ("str", "word"):
            raise ValueError("variable or string expected")
        if (a[0] == "word") == (b[0] == "word") or (a[0] == "word" and a[1] not in env) or \
                (b[0] == "word" and b[1] not in env):
            unknown = True
            return False
        key = a[1] if a[0] == "word" else b[1]
        left = env[a[1]] if a[0] == "word" else a[1][1:-1]
        right = env[b[1]] if b[0] == "word" else b[1][1:-1]
        if op in ("in", "not in"):
            return (left in right) == (op == "in")
        r = _version_op(op, left, right) if key in _VERSION_FIELDS else _string_op(op, left, right)
        if r is None:
            unknown = True
            return False
        return r

    def conj():
        v = expr()
        while peek()[0] == "and":
            take()
            v = expr() and v      # every atom is read: one None anywhere makes the marker None (packaging raises)
        return v

    def disj():
        v = conj()
        while peek()[0] == "or":
            take()
            v = conj() or v
        return v

    try:
        v = disj()
    except (ValueError, IndexError):
        return None
    if pos != len(toks) or unknown:
        return None
    return bool(v)


def marker_applies(marker: str) -> Optional[bool]:
    """Evaluate a PEP 508 marker for THIS interpreter (spec/SBOM_INGEST.md, installed floor, 0.13.0): `packaging` when
    importable, otherwise `_fallback_marker`. None = could not evaluate (outside the grammar, unknown variable, undefined
    comparison): the requirement is kept and counted."""
    marker = marker.strip()
    if not marker:
        return True
    try:
        from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName  # type: ignore
    except ImportError:
        return _fallback_marker(marker)
    try:
        return bool(Marker(marker).evaluate())
    except (UndefinedEnvironmentName, InvalidMarker, UndefinedComparison):   # 18/11/2026: UndefinedComparison was
        return None                                                          # a traceback


def _req_name(req: str) -> str:
    s = req.split(";")[0].strip()
    for sep in ("[", " ", "(", "<", ">", "=", "!", "~"):
        i = s.find(sep)
        if i > 0:
            s = s[:i]
    return s.strip()


def installed_license(meta: Any) -> str:
    """PEP 639 `License-Expression` first (cryptography ships it since 46.0.0 with the legacy `License` field empty —
    measured on PyPI metadata 20/09/2026; cffi 2.0 and pycparser 3.0 likewise), then the legacy `License` field,
    then the first `License ::` trove classifier."""
    for key in ("License-Expression", "License"):
        v = (meta.get(key) or "").strip()
        if v and v.upper() != "UNKNOWN":
            return v[:80]
    for c in meta.get_all("Classifier") or []:
        if c.startswith("License ::"):
            return c.split("::")[-1].strip()[:80]
    return ""


_WHITE_SPACE = re.compile(r"\s+")


def _expression_parts(value: str) -> List[str]:
    """The text between the operators ` OR `, ` AND `, ` WITH ` (white space, the word, white space), left to right
    (spec/SBOM_INGEST.md, rules 12 and 13(3)). One pass over the runs of white space. Until 0.13.0 this was
    re.split(r"\s+(?:OR|AND|WITH)\s+", value): the same parts, quadratic in a run of white space (20/11/2026: a licence
    of 32 kB of spaces took 5.8 s in `record_sbom`)."""
    runs = [m.span() for m in _WHITE_SPACE.finditer(value)]
    parts, last, i = [], 0, 0
    while i < len(runs):
        start, end = runs[i]
        word = next((w for w in ("OR", "AND", "WITH") if value.startswith(w, end)), None)
        if word is not None and i + 1 < len(runs) and runs[i + 1][0] == end + len(word):
            parts.append(value[last:start])
            last = runs[i + 1][1]
            i += 1                       # the white space after the word is the operator's: it starts no other one
        i += 1
    parts.append(value[last:])
    return parts


def is_spdx_expression(value: str) -> bool:
    """A compound SPDX expression (`A OR B`, `A AND B`, `A WITH exc`) whose atoms are listed identifiers."""
    parts = _expression_parts(value)
    return len(parts) > 1 and all(is_spdx_id(p.strip("() ")) or re.search(r"-exception(-[0-9.]+)?$", p.strip("() ")) for p in parts)


def sbom_from_installed(product_id: str, product_version: str, top_level: List[str], transitive: bool = False) -> SBOMRecord:
    """Components resolved from THIS interpreter's installed distributions. A dependency that is declared but not
    installed is recorded with version 'NOT-INSTALLED' (the floor is honest, not padded)."""
    from importlib import metadata as md
    comps: Dict[str, SBOMComponent] = {}
    edges: List[List[str]] = []
    walked: List[str] = []                      # keys whose Requires-Dist was READ (only these may assert "no dependencies")
    unevaluated = 0
    if not isinstance(top_level, (list, tuple)) or not all(isinstance(n, str) and n.strip() for n in top_level):
        raise ValueError("top_level: a list of package names")     # 18/11/2026: "pip" gave the components "p" and "i"
    todo = [("", n) for n in top_level]         # (parent key, name); "" = the product
    seen = set()
    while todo:
        parent, name = todo.pop(0)
        key = _norm_key(name)
        if [parent, key] not in edges and parent != key:
            edges.append([parent, key])
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = md.distribution(name)
            ver = dist.version
            lic = installed_license(dist.metadata)
            comps[key] = SBOMComponent(name=dist.metadata["Name"], version=ver[:SCHEMA_TEXT_MAX], purl=pypi_purl(key, ver[:SCHEMA_TEXT_MAX]), license=lic)
            if transitive:
                walked.append(key)
                for r in dist.requires or []:
                    if _is_extra_requirement(r):
                        continue
                    marker = r.split(";", 1)[1] if ";" in r else ""
                    applies = marker_applies(marker)
                    if applies is False:
                        continue                # a dependency of ANOTHER environment (python_version, platform…) is not one here
                    if applies is None:
                        unevaluated += 1        # kept, conservatively, and counted
                    todo.append((key, _req_name(r)))
        except md.PackageNotFoundError:
            comps[key] = SBOMComponent(name=name, version="NOT-INSTALLED")
    source = {"format": "installed", "generator": "cra-evidence:importlib.metadata", "generator_version": sys.version.split()[0],
              "requires_dist_read": walked, "markers_unevaluated_kept": unevaluated, "dependency_edges": len(edges)}
    return SBOMRecord(product_id=product_id, product_version=product_version, components=list(comps.values()),
                      depth="transitive" if transitive else "top-level-only", edges=edges, source=source)


def _norm_key(name: str) -> str:
    """PEP 503 normalisation: the key under which a distribution is looked up and an edge is recorded."""
    return re.sub(r"[-_.]+", "-", name.lower())


def _load_document(path: str, raw: Optional[bytes] = None) -> Tuple[bytes, Any]:
    """A generator document is third-party input, read ONCE: the bytes that are parsed are the bytes that are
    fingerprinted (two reads could see two versions of a file still being written). A nesting that exhausts the
    parser, a duplicate key (two readers would resolve it differently) or invalid UTF-8 is a malformed document
    (ValueError), never a crash."""
    from .ledger import FileTooLarge, parse_line, read_regular
    if raw is None:
        try:                       # 18/11/2026: open() blocked on a FIFO and read /dev/zero until killed (cra sbom, cra vex,
            raw = read_regular(path, MAX_SOURCE_BYTES)     # cra vuln --vex): a regular file, opened without blocking
        except FileTooLarge:
            raise ValueError(f"document exceeds {MAX_SOURCE_BYTES} bytes: refused unread (third-party input is bounded before it is read)") from None
    try:
        return raw, parse_line(raw.decode("utf-8"), allow_floats=True)
    except RecursionError:
        raise ValueError("document malformed: JSON nested too deep") from None
    except UnicodeDecodeError:
        raise ValueError("document malformed: not UTF-8") from None
    except json.JSONDecodeError as e:          # not JSON at all: say which format it is when it is a known one
        raise ValueError(_not_json_reason(raw, e)) from None


# What `cra sbom` reads is JSON; a document in another serialisation is named in the refusal (CHANGELOG, 0.11.0,
# "a refused document exits 2 with one line"). Recognised from the start of the text, never parsed.
_SPDX_TAG_VALUE = re.compile(r"\A(?:[ \t]*(?:#[^\n]*)?\r?\n)*[ \t]*SPDXVersion:[ \t]*SPDX-")


def _not_json_reason(raw: bytes, err: "json.JSONDecodeError") -> str:
    head = raw[:4096].decode("utf-8", "replace")
    if head.startswith("\ufeff"):
        return "document malformed: not JSON (it starts with a byte order mark, U+FEFF)"
    if _SPDX_TAG_VALUE.match(head):
        return ("SPDX tag-value is not supported: give the SPDX JSON document (spdx/tools-python converts it: "
                "\"pyspdxtools -i <file>.spdx -o <file>.spdx.json --novalidation\")")
    if head.lstrip().startswith("<"):
        if "cyclonedx.org/schema/bom" in head:
            return ("CycloneDX XML is not supported: give the CycloneDX JSON document (CycloneDX/cyclonedx-cli converts it: "
                    "\"cyclonedx convert --input-file <file>.xml --output-file <file>.json\")")
        if "rdf:RDF" in head and "spdx.org/rdf" in head:
            return "SPDX RDF/XML is not supported: give the SPDX JSON document"
        return "document malformed: not JSON (XML)"
    return f"document malformed: not JSON ({err.msg} at line {err.lineno} column {err.colno})"


def _fingerprint_bytes(raw: bytes, path: str) -> Dict[str, Any]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw), "file": os.path.basename(path)}


SCHEMA_TEXT_MAX = 1024   # CycloneDX 1.6/1.7 `version` maxLength: a longer value would make the index export schema-invalid


def _s(v: Any) -> str:
    """A text field of a generator document: only a string is text; anything else is empty, never stringified."""
    return v if isinstance(v, str) else ""


def _cdx_generator(d: Dict[str, Any]) -> Tuple[str, str]:
    """metadata.tools as 1.5+ {components:[...]} or the legacy list of {vendor,name,version}: (name, version)."""
    try:
        tools = (d.get("metadata", {}) or {}).get("tools", {})
        comp = tools.get("components", []) if isinstance(tools, dict) else tools
        if isinstance(comp, list) and comp and isinstance(comp[0], dict):
            return _s(comp[0].get("name")), _s(comp[0].get("version"))
    except Exception:  # noqa: BLE001
        pass
    return "", ""


# The top level of the official JSON schemas (`properties`, `required`, `additionalProperties`), read 04/11/2026 from
# CycloneDX/specification bom-1.2 … bom-1.7.schema.json. 1.2 and 1.3 leave the top level open.
_CDX_TOP_14 = frozenset({"$schema", "bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "services",
                         "externalReferences", "dependencies", "compositions", "vulnerabilities", "signature"})
_CDX_TOP_15 = _CDX_TOP_14 | {"annotations", "formulation", "properties"}
_CDX_TOP_16 = _CDX_TOP_15 | {"declarations", "definitions"}
_CDX_TOP_LEVEL: Dict[str, Optional[frozenset]] = {"1.2": None, "1.3": None, "1.4": _CDX_TOP_14, "1.5": _CDX_TOP_15, "1.6": _CDX_TOP_16,
                                                  "1.7": _CDX_TOP_16 | {"citations"}}


def _cdx_top_level_valid(d: Dict[str, Any]) -> None:
    """A document without `components`: the only members that say it is a BOM are the ones around them, so they are read
    as the schema of the declared version reads them. Raises ValueError (as a document with no `components` always did)
    on what no schema of 1.2 … 1.7 admits: a `specVersion` outside them, `version` missing up to 1.4, an unknown member."""
    spec = d.get("specVersion")
    if not isinstance(spec, str) or spec not in _CDX_TOP_LEVEL:
        raise ValueError("CycloneDX malformed: without 'components' the document needs a 'specVersion' from 1.2 to 1.7")
    if spec in ("1.2", "1.3", "1.4") and "version" not in d:
        raise ValueError(f"CycloneDX malformed: 'version' is required in {spec}")
    known = _CDX_TOP_LEVEL[spec]
    unknown = [] if known is None else sorted(k for k in d if k not in known)
    if unknown:
        raise ValueError(f"CycloneDX malformed: member outside the {spec} schema: " + ", ".join(unknown)[:120])


# Schema check of an ingested CycloneDX document (CHANGELOG, 0.11.0, rules 1-4). The official schemas of
# CycloneDX/specification at 6470e34 ship in data/cyclonedx/ (SHA-256 in SOURCES.txt). jsonschema is the optional extra
# [schema]: it skips a `format` it has no checker for without saying so, so every format the schemas use must have one.
_CDX_SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cyclonedx")
_CDX_SCHEMA_VERSIONS = ("1.2", "1.3", "1.4", "1.5", "1.6", "1.7")
_FORMATS_NEEDED = ("date", "date-time", "idn-email", "iri-reference", "uri")
_VALIDATORS: Dict[str, Any] = {}

# `iri-reference`: RFC 3987 §2.2 ABNF (with the rules it takes from RFC 3986) as one regular expression, matched whole.
# jsonschema[format-nongpl] calls rfc3987-syntax, an Earley parser: ~0.1 s per URL, 220 s for an SBOM with 2,476 URLs
# (CHANGELOG, 0.11.0). Each repetition below is over characters that the next token cannot start with ("/", "?", "#",
# "@", ":", "]" end them), so a failed match backtracks a bounded number of steps per character: linear time.
_UCSCHAR = ("\u00a0-\ud7ff\uf900-\ufdcf\ufdf0-\uffef"
            "\U00010000-\U0001fffd\U00020000-\U0002fffd\U00030000-\U0003fffd\U00040000-\U0004fffd"
            "\U00050000-\U0005fffd\U00060000-\U0006fffd\U00070000-\U0007fffd\U00080000-\U0008fffd"
            "\U00090000-\U0009fffd\U000a0000-\U000afffd\U000b0000-\U000bfffd\U000c0000-\U000cfffd"
            "\U000d0000-\U000dfffd\U000e1000-\U000efffd")
_IPRIVATE = "\ue000-\uf8ff\U000f0000-\U000ffffd\U00100000-\U0010fffd"
_IUNRESERVED = "A-Za-z0-9\\-._~" + _UCSCHAR
_SUB_DELIMS = "!$&'()*+,;="
_PCT = "%[0-9A-Fa-f]{2}"
_IPCHAR = f"(?:[{_IUNRESERVED}{_SUB_DELIMS}:@]|{_PCT})"
_H16 = "[0-9A-Fa-f]{1,4}"
_DEC_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_IPV4 = f"{_DEC_OCTET}\\.{_DEC_OCTET}\\.{_DEC_OCTET}\\.{_DEC_OCTET}"
_LS32 = f"(?:{_H16}:{_H16}|{_IPV4})"
_IPV6 = "(?:" + "|".join([                              # the nine forms of RFC 3986 §3.2.2, in its order
    f"(?:{_H16}:){{6}}{_LS32}",
    f"::(?:{_H16}:){{5}}{_LS32}",
    f"(?:{_H16})?::(?:{_H16}:){{4}}{_LS32}",
    f"(?:(?:{_H16}:){{0,1}}{_H16})?::(?:{_H16}:){{3}}{_LS32}",
    f"(?:(?:{_H16}:){{0,2}}{_H16})?::(?:{_H16}:){{2}}{_LS32}",
    f"(?:(?:{_H16}:){{0,3}}{_H16})?::{_H16}:{_LS32}",
    f"(?:(?:{_H16}:){{0,4}}{_H16})?::{_LS32}",
    f"(?:(?:{_H16}:){{0,5}}{_H16})?::{_H16}",
    f"(?:(?:{_H16}:){{0,6}}{_H16})?::"]) + ")"
_IPVFUTURE = f"[vV][0-9A-Fa-f]+\\.[A-Za-z0-9\\-._~{_SUB_DELIMS}:]+"     # "v" is case-insensitive (RFC 2234 §2.3)
_IHOST = f"(?:\\[(?:{_IPV6}|{_IPVFUTURE})\\]|(?:[{_IUNRESERVED}{_SUB_DELIMS}]|{_PCT})*)"   # IPv4address is a subset of ireg-name
_IAUTHORITY = f"(?:(?:[{_IUNRESERVED}{_SUB_DELIMS}:]|{_PCT})*@)?{_IHOST}(?::[0-9]*)?"
_IPATH_ABEMPTY = f"(?:/{_IPCHAR}*)*"
_QUERY_FRAGMENT = f"(?:\\?(?:{_IPCHAR}|[{_IPRIVATE}/?])*)?(?:#(?:{_IPCHAR}|[/?])*)?"
_IRI = (f"[A-Za-z][A-Za-z0-9+\\-.]*:(?://{_IAUTHORITY}{_IPATH_ABEMPTY}|/(?:{_IPCHAR}+{_IPATH_ABEMPTY})?"
        f"|{_IPCHAR}+{_IPATH_ABEMPTY}|){_QUERY_FRAGMENT}")
_IRELATIVE_REF = (f"(?://{_IAUTHORITY}{_IPATH_ABEMPTY}|/(?:{_IPCHAR}+{_IPATH_ABEMPTY})?"
                  f"|(?:[{_IUNRESERVED}{_SUB_DELIMS}@]|{_PCT})+{_IPATH_ABEMPTY}|){_QUERY_FRAGMENT}")
IRI_REFERENCE = re.compile(f"(?:{_IRI}|{_IRELATIVE_REF})")
# RFC 3986 §3 `URI` (absolute, ASCII): the same rules without the IRI's ucschar / iprivate (spec/SBOM_INGEST.md, SPDX
# rule 7: the SPDX §10.4 format "Uniform Resource Locator", RFC 3986 being the specification's normative reference).
_UNRESERVED = "A-Za-z0-9\\-._~"
_PCHAR = f"(?:[{_UNRESERVED}{_SUB_DELIMS}:@]|{_PCT})"
_HOST = f"(?:\\[(?:{_IPV6}|{_IPVFUTURE})\\]|(?:[{_UNRESERVED}{_SUB_DELIMS}]|{_PCT})*)"
_AUTHORITY = f"(?:(?:[{_UNRESERVED}{_SUB_DELIMS}:]|{_PCT})*@)?{_HOST}(?::[0-9]*)?"
_PATH_ABEMPTY = f"(?:/{_PCHAR}*)*"
URI = re.compile(f"[A-Za-z][A-Za-z0-9+\\-.]*:(?://{_AUTHORITY}{_PATH_ABEMPTY}|/(?:{_PCHAR}+{_PATH_ABEMPTY})?"
                 f"|{_PCHAR}+{_PATH_ABEMPTY}|)(?:\\?(?:{_PCHAR}|[/?])*)?(?:#(?:{_PCHAR}|[/?])*)?")


def is_iri_reference(instance: Any) -> bool:
    """JSON Schema `iri-reference`: RFC 3987 §2.2 `IRI-reference`. A non-string is not this format's business (True)."""
    return not isinstance(instance, str) or IRI_REFERENCE.fullmatch(instance) is not None


def _format_checker(jsonschema: Any) -> Any:
    """jsonschema's draft-07 format checker with `iri-reference` replaced by is_iri_reference — a copy: the library's
    own checker is never modified (another caller in the same process keeps jsonschema's behaviour)."""
    fc = copy.copy(jsonschema.Draft7Validator.FORMAT_CHECKER)
    fc.checkers = dict(fc.checkers)
    fc.checkers["iri-reference"] = (is_iri_reference, ())
    return fc


def _jsonschema():
    import jsonschema                      # noqa: F401  (the extra [schema])
    from referencing import Registry, Resource
    return jsonschema, Registry, Resource


def _cdx_validator(spec: str):
    """(validator, None) or (None, reason it cannot run)."""
    if spec in _VALIDATORS:
        return _VALIDATORS[spec], None
    try:
        jsonschema, Registry, Resource = _jsonschema()
    except ImportError as e:
        return None, f"jsonschema is not installed ({e}); install omega-cra-evol[schema]"
    checker = jsonschema.Draft7Validator.FORMAT_CHECKER
    missing = [f for f in _FORMATS_NEEDED if f not in checker.checkers]
    if missing:
        return None, ("jsonschema cannot check the format(s) " + ", ".join(missing) +
                      "; install omega-cra-evol[schema] (jsonschema[format-nongpl] >= 4.25)")
    docs = {}
    for name in sorted(os.listdir(_CDX_SCHEMA_DIR)):
        if name.endswith(".schema.json"):
            with open(os.path.join(_CDX_SCHEMA_DIR, name), "rb") as fh:
                docs[name] = json.loads(fh.read().decode("utf-8"))
    pairs = [(n, Resource.from_contents(d)) for n, d in docs.items()]
    pairs += [(d["$id"], Resource.from_contents(d)) for d in docs.values() if isinstance(d.get("$id"), str)]
    # uniqueItems in linear time (jsonschema compares objects pairwise: 4,000 components took 16 s, 20,000 minutes),
    # with the same equality as jsonschema (_utils.equal: true is not 1, 1 equals 1.0, objects and arrays by value)
    why = _ecma_ready(list(docs.values()))
    if why:
        return None, why
    cls = jsonschema.validators.extend(jsonschema.Draft7Validator, {"uniqueItems": _unique_items, **ECMA_KEYWORDS})
    try:
        v = cls(docs[f"bom-{spec}.schema.json"], registry=Registry().with_resources(pairs), format_checker=_format_checker(jsonschema))
    except TypeError as e:                 # a jsonschema older than 4.18 (no `registry`) next to a separate `referencing`
        return None, f"jsonschema too old ({e}); install omega-cra-evol[schema] (jsonschema[format-nongpl] >= 4.25)"
    _VALIDATORS[spec] = v
    return v, None


# `pattern` as an ECMA-262 regular expression with the "u" flag (CHANGELOG, 0.11.0: JSON Schema
# draft-07 Validation §4.3, 2020-12 Core §6.4). jsonschema uses Python's re.search, which reads `$`, `.`, `\d`, `\w` and
# `\s` differently; they are translated, and any construct this translation does not cover raises EcmaPatternUnsupported
# (the check is then "not checked", never a guess).
class EcmaPatternUnsupported(ValueError):
    pass


_ECMA_SPACE = "\t\n\x0b\x0c\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_ECMA_CLASS_ESC = {"d": "0-9", "w": "A-Za-z0-9_", "s": _ECMA_SPACE}
_ECMA_ESC = {"d": "[0-9]", "D": "[^0-9]", "w": "[A-Za-z0-9_]", "W": "[^A-Za-z0-9_]", "s": "[" + _ECMA_SPACE + "]",
             "S": "[^" + _ECMA_SPACE + "]"}
_ECMA_PATTERNS: Dict[str, Any] = {}


def ecma_pattern(p: str) -> "re.Pattern[str]":
    """the compiled Python pattern with the meaning of the ECMA-262 pattern `p` ("u" flag, no other flag); a pattern
    ECMA-262 refuses with "u", or a construct not translated here, raises EcmaPatternUnsupported"""
    if p in _ECMA_PATTERNS:
        return _ECMA_PATTERNS[p]
    bad = lambda why: EcmaPatternUnsupported(f"pattern {p[:80]!r}: {why}")   # noqa: E731
    out, i, cls = [], 0, False
    atom = False           # the last token written can take a quantifier (not a start, "|", "(", an assertion)
    quant = 0              # 1: a quantifier was just written, 2: and its lazy "?"; no other quantifier may follow
    groups: List[bool] = []    # per open group: is it a lookahead (which "u" forbids to quantify)
    while i < len(p):
        c = p[i]
        if c == "\\":
            e = p[i + 1:i + 2]
            if not e:
                raise bad("a trailing backslash")
            if e in "dws" and cls:
                if (p[i - 1:i] == "-" and p[i - 2:i - 1] not in ("[", "^")) or \
                        (p[i + 2:i + 3] == "-" and p[i + 3:i + 4] != "]"):
                    raise bad("a class escape at the end of a range")
                out.append(_ECMA_CLASS_ESC[e])
            elif e in _ECMA_ESC and not cls:
                out.append(_ECMA_ESC[e])
            elif e in "tnrfv":
                out.append("\\" + e)
            elif e == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", p[i + 2:i + 4]):
                out.append(p[i:i + 4]); i += 4; atom, quant = not cls or atom, 0; continue
            elif e == "u" and re.fullmatch(r"[0-9A-Fa-f]{4}", p[i + 2:i + 6]):
                if 0xD800 <= int(p[i + 2:i + 6], 16) <= 0xDFFF:     # with "u" a pair of escapes is ONE code point
                    raise bad(f"the surrogate escape \\{p[i + 1:i + 6]} is not translated")
                out.append(p[i:i + 6]); i += 6; atom, quant = not cls or atom, 0; continue
            elif e in "^$\\.*+?()[]{}|/" or (e == "-" and cls):     # the identity escapes "u" allows
                out.append("\\" + e)
            else:
                raise bad(f"the escape \\{e} is not translated")
            i += 2
            if not cls:
                atom, quant = True, 0
            continue
        if cls:
            if c == "]":
                cls, atom, quant = False, True, 0
            elif c == "[":
                c = "\\["                              # a literal "[" in an ECMA class; Python warns on it
            out.append(c)
        elif c == "[":
            cls = True
            out.append(c)
            if p[i + 1:i + 2] == "^":
                out.append("^"); i += 1
            if p[i + 1:i + 2] == "]":
                raise bad("an empty class")
        elif c == "(":
            kind = p[i + 1:i + 3] if p[i + 1:i + 2] == "?" else ""
            if kind and kind not in ("?:", "?=", "?!"):
                raise bad(f"the group ({kind} is not translated")
            groups.append(kind in ("?=", "?!"))
            out.append("(" + kind); i += 1 + len(kind); atom, quant = False, 0; continue
        elif c == ")":
            if not groups:
                raise bad("a lone ')'")
            out.append(c); atom, quant = not groups.pop(), 0
        elif c in "*+?{":
            m = re.match(r"\{[0-9]+(?:,[0-9]*)?\}", p[i:]) if c == "{" else None
            if c == "{" and m is None:
                raise bad("a '{' that is not a quantifier")
            if quant == 1 and c == "?":
                out.append("?"); i += 1; quant = 2; continue      # the lazy mark of the quantifier just written
            if quant or not atom:
                raise bad("a quantifier with nothing to repeat")
            if m and len(m.group(0)) > 2 and "," in m.group(0)[1:-1]:
                lo, hi = m.group(0)[1:-1].split(",")
                if hi and int(lo) > int(hi):
                    raise bad("a quantifier out of order")
            tok = m.group(0) if m else c
            out.append(tok); i += len(tok); atom, quant = False, 1; continue
        elif c in "}]":
            raise bad(f"a lone {c!r}")
        elif c == "|":
            out.append(c); atom, quant = False, 0
        elif c == "^":
            out.append(c); atom, quant = False, 0
        elif c == "$":
            out.append("(?![\\s\\S])"); atom, quant = False, 0   # the end of the input, not "or before a final newline"
        elif c == ".":
            out.append("[^\\n\\r\\u2028\\u2029]"); atom, quant = True, 0
        else:
            out.append(c); atom, quant = True, 0
        i += 1
    if cls:
        raise bad("an unterminated class")
    try:
        r = re.compile("".join(out))
    except re.error as e:
        raise bad(str(e)) from None
    _ECMA_PATTERNS[p] = r
    return r


def schema_patterns(schema: Any) -> Tuple[List[str], int]:
    """every `pattern` value of a schema, and how many `patternProperties` it holds (iterative walk)"""
    found, pp, stack = [], 0, [schema]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "pattern" and isinstance(v, str):
                    found.append(v)
                    continue
                if k == "patternProperties":
                    pp += 1
                stack.append(v)
        elif isinstance(o, list):
            stack.extend(o)
    return found, pp


def _pattern(validator, patrn, instance, schema):
    if validator.is_type(instance, "string") and not ecma_pattern(patrn).search(instance):
        from jsonschema.exceptions import ValidationError
        yield ValidationError(f"{instance!r} does not match {patrn!r}")


ECMA_KEYWORDS = {"pattern": _pattern}


def _ecma_ready(docs: List[Any]) -> Optional[str]:
    """None when every pattern of these schemas translates; else the reason (the check is then not run)"""
    for d in docs:
        found, pp = schema_patterns(d)
        if pp:      # jsonschema also reads patternProperties inside additionalProperties / unevaluatedProperties, with re
            return "the schema holds patternProperties, which this check does not read as ECMA-262"
        for p in found:
            try:
                ecma_pattern(p)
            except EcmaPatternUnsupported as e:
                return f"{e} (ECMA-262 regular expression not translated)"
    return None


def _uniq_key(x: Any) -> Any:
    if isinstance(x, bool):
        return ("b", x)
    if isinstance(x, (int, float)):
        return ("n", x)                    # 1 and 1.0 share hash and equality, as in jsonschema
    if isinstance(x, str):
        return ("s", x)
    if isinstance(x, list):
        return ("l", tuple(_uniq_key(i) for i in x))
    if isinstance(x, dict):
        return ("d", frozenset((k, _uniq_key(v)) for k, v in x.items()))
    if x is None:
        return ("z", None)
    raise TypeError("not a JSON value")    # not from a JSON parser: jsonschema's own comparison decides


def _unique_items(validator, ui, instance, schema):
    if ui and validator.is_type(instance, "array"):
        from jsonschema.exceptions import ValidationError
        try:
            first: Dict[Any, int] = {}
            for i, e in enumerate(instance):
                j = first.setdefault(_uniq_key(e), i)
                if j != i:                 # the reason first: jsonschema's message starts with the whole array
                    yield ValidationError(f"has non-unique elements (items {j} and {i} are equal)")
                    return
        except TypeError:
            from jsonschema._utils import uniq
            if not uniq(instance):
                yield ValidationError(f"{instance!r} has non-unique elements")


def cyclonedx_schema_check(d: Any) -> Tuple[str, str]:
    """("conformant" | "not_conformant" | "not_checked", the text recorded in source.schema_check)."""
    spec = d.get("specVersion") if isinstance(d, dict) else None
    if not isinstance(spec, str) or spec not in _CDX_SCHEMA_VERSIONS:
        return "not_checked", f"not checked: no official schema here for specVersion {spec!r} (1.2 to 1.7)"
    v, why = _cdx_validator(spec)
    if v is None:
        return "not_checked", "not checked: " + why
    from jsonschema.exceptions import best_match
    from .canonical import deep_recursion
    try:
        with deep_recursion():             # a document the parser accepts (nesting <= 512) must be checkable too
            err = best_match(v.iter_errors(d))
    except RecursionError:
        raise ValueError("CycloneDX malformed: nested too deep for the schema check") from None
    if err is None:
        return "conformant", f"conformant to bom-{spec}.schema.json"
    where = "/".join(str(x) for x in err.absolute_path) or "(document)"
    return "not_conformant", f"not conformant to bom-{spec}.schema.json at {where}: {err.message}"[:300]


# Schema check of an ingested SPDX document (CHANGELOG, 0.11.0, SPDX rules 1-5; spec/SBOM_INGEST.md, rule 6). The
# official schemas ship in data/spdx/ (SHA-256 in SOURCES.txt); none of them uses a `format` keyword, so jsonschema alone
# checks them. SPDX-2.2: the corrected schema of spdx/spdx-spec development/v2.2.2 (the tag v2.2.2 holds a 2.2.1-era
# schema whose referenceCategory enum contradicts §7.21, spdx-spec#798 / #836); SPDX-2.3: the maintenance release 2.3.1.
_SPDX3_SCHEMA = "spdx-json-schema-3.0.1.json"
_SPDX_SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "spdx")
_SPDX2_SCHEMAS = {"SPDX-2.2": "spdx-schema-v2.2.2-4694d1f.json", "SPDX-2.3": "spdx-schema-v2.3.1.json"}
_SPDX_DIALECT = {_SPDX3_SCHEMA: "Draft202012Validator", "spdx-schema-v2.3.1.json": "Draft201909Validator"}
SPDX3_CONTEXT_301 = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
_SPDX_VALIDATORS: Dict[str, Any] = {}


def _spdx_validator(name: str):
    """(validator, None) or (None, reason it cannot run)."""
    if name in _SPDX_VALIDATORS:
        return _SPDX_VALIDATORS[name], None
    try:
        import jsonschema                  # the extra [schema]
    except ImportError as e:
        return None, f"jsonschema is not installed ({e}); install omega-cra-evol[schema]"
    dialect = _SPDX_DIALECT.get(name, "Draft7Validator")
    cls = getattr(jsonschema, dialect, None)
    if cls is None:                        # a jsonschema older than 4.0 has no 2019-09 / 2020-12 validator
        return None, f"jsonschema too old (no {dialect}); install omega-cra-evol[schema]"
    with open(os.path.join(_SPDX_SCHEMA_DIR, name), "rb") as fh:
        doc = json.loads(fh.read().decode("utf-8"))
    cls.check_schema(doc)
    why = _ecma_ready([doc])
    if why:
        return None, why
    v = jsonschema.validators.extend(cls, ECMA_KEYWORDS)(doc)
    _SPDX_VALIDATORS[name] = v
    return v, None


def spdx_schema_check(d: Any) -> Tuple[str, str]:
    """("conformant" | "not_conformant" | "unsupported" | "not_checked", the text recorded in source.schema_check).
    `unsupported`: a version without an official schema here (refused unless --allow-nonconformant, rule 2);
    `not_checked`: the check cannot run on this host (recorded, never floor met, rule 3)."""
    if isinstance(d, dict) and "spdxVersion" in d:
        ver = d.get("spdxVersion")
        name = _SPDX2_SCHEMAS.get(ver) if isinstance(ver, str) else None
        if name is None:
            return "unsupported", (f"not checked: no official schema here for spdxVersion {str(ver)[:40]!r} "
                                   f"({', '.join(sorted(_SPDX2_SCHEMAS))})")
    else:
        ctx = d.get("@context") if isinstance(d, dict) else None
        has_301 = ctx == SPDX3_CONTEXT_301 or (isinstance(ctx, list) and SPDX3_CONTEXT_301 in ctx)
        if not has_301:
            return "unsupported", (f"not checked: no official schema here for @context {json.dumps(ctx)[:120]} "
                                   f"(SPDX 3.0.1: {SPDX3_CONTEXT_301!r})")
        name = _SPDX3_SCHEMA
    v, why = _spdx_validator(name)
    if v is None:
        return "not_checked", "not checked: " + why
    from jsonschema.exceptions import best_match
    from .canonical import deep_recursion
    try:
        with deep_recursion():             # a document the parser accepts (nesting <= 512) must be checkable too
            err = best_match(v.iter_errors(d))
    except RecursionError:
        raise ValueError("SPDX malformed: nested too deep for the schema check") from None
    if err is None:
        return "conformant", f"conformant to {name}"
    where = "/".join(str(x) for x in err.absolute_path) or "(document)"
    return "not_conformant", f"not conformant to {name} at {where}: {err.message}"[:300]


def _cdx_identifiers(d: Any) -> List[str]:
    """CycloneDX rule 5 (spec/SBOM_INGEST.md): the string values of every `bom-ref` member of an object, in document
    order, except in an item of a `patentAssertions` array (1.7 JSON: a reference to a patent). Iterative: a document the
    parser accepts may nest 512 levels."""
    out: List[str] = []
    stack: List[Tuple[Any, Optional[str]]] = [(d, None)]
    while stack:
        node, parent_key = stack.pop()
        if isinstance(node, dict):
            r = node.get("bom-ref")
            if isinstance(r, str) and parent_key != "patentAssertions":
                out.append(r)
            stack.extend((v, k) for k, v in reversed(list(node.items())))
        elif isinstance(node, list):
            stack.extend((v, parent_key) for v in reversed(node))
    return out


_IN_TOTO_STATEMENTS = ("https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1")
_CDX_PREDICATE = re.compile(r"https://cyclonedx\.org/bom(?:/v[0-9]+(?:\.[0-9]+)*)?")
_SPDX_PREDICATE = re.compile(r"https://spdx\.dev/Document(?:/v[0-9]+(?:\.[0-9]+)*)?")
_SYFT_JSON_REFUSED = ('Syft JSON is not supported: convert it with "syft convert <file> -o cyclonedx-json" '
                     '(or -o spdx-json)')


def _unwrap(d: Any, want: str) -> Tuple[Any, Dict[str, Any]]:
    """spec/SBOM_INGEST.md rules 10 and 11 (0.13.0): an in-toto Statement whose predicate is a CycloneDX BOM / an SPDX
    document gives its predicate (and what `source` says of the wrapper); a Syft JSON document or a DSSE envelope is
    refused by name; anything else is returned as it is. `want`: "cyclonedx" or "spdx"."""
    if not isinstance(d, dict):
        return d, {}
    desc = d.get("descriptor")
    if isinstance(desc, dict) and desc.get("name") == "syft" and "artifacts" in d:
        raise ValueError(_SYFT_JSON_REFUSED)
    if {"payloadType", "payload", "signatures"} <= set(d):
        raise ValueError("a DSSE envelope is not read: give the in-toto Statement it carries (its signature is not "
                         "verified here either way)")
    if "_type" not in d and "predicateType" not in d:
        return d, {}
    if d.get("_type") not in _IN_TOTO_STATEMENTS:
        raise ValueError(f"in-toto: _type {str(d.get('_type'))[:120]!r} is not an in-toto Statement v1 or v0.1")
    pt = d.get("predicateType")
    kind = ("cyclonedx" if isinstance(pt, str) and _CDX_PREDICATE.fullmatch(pt) else
            "spdx" if isinstance(pt, str) and _SPDX_PREDICATE.fullmatch(pt) else "")
    if not kind:
        raise ValueError(f"in-toto Statement: predicateType {str(pt)[:120]!r} is not a CycloneDX BOM or an SPDX document")
    if kind != want:
        raise ValueError(f"in-toto Statement of {'a CycloneDX BOM' if kind == 'cyclonedx' else 'an SPDX document'}: "
                         f"give it with --from-{kind}")
    if not isinstance(d.get("predicate"), dict):
        raise ValueError("in-toto Statement: predicate is not a JSON object")
    subj = d.get("subject")
    return d["predicate"], {"wrapper": "in-toto-statement", "wrapper_predicate_type": pt,
                            "wrapper_subjects": len(subj) if isinstance(subj, list) else 0}


_BSI_TR_VERSION = "2.1.0"


def _bsi_tr_note(fmt: str, version: str) -> Dict[str, Any]:
    """spec/SBOM_INGEST.md, "The format version and BSI TR-03183-2" (0.13.0): a notice, never a refusal"""
    def rel(v: str) -> Tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"[0-9]+", v)[:3])
    met = rel(version) >= ((1, 6) if fmt == "cyclonedx" else (3, 0, 1))
    return {"version": _BSI_TR_VERSION, "format_minimum_met": met,
            "note": ("BSI TR-03183-2 v2.1.0 §4 asks CycloneDX 1.6 or higher / SPDX 3.0.1 or higher; informative, the CRA "
                     "does not make the TR binding; no other field of the TR is checked")}


def sbom_from_cyclonedx(path: str, product_id: str, product_version: str, raw: Optional[bytes] = None,
                        allow_nonconformant: bool = False) -> SBOMRecord:
    """Ingest a CycloneDX JSON (1.2 … 1.7) from ANY generator: components are walked recursively (a generator may
    nest `components[].components`), a component without a name is skipped (an unknown `type` is indexed as
    "library" — the declared value survives in `source.component_types` and in the stored bytes), a malformed document raises. The record's
    `source` says what the document declared (spec version, generator, total/nested component count, dependency
    edges, component types) and how many duplicates (same name+version+purl at two locations, as Syft emits for a
    workflow file referenced twice) the index merged — the count the auditor reads is the generator's, not ours."""
    raw, d = _load_document(path, raw)
    d, wrapper = _unwrap(d, "cyclonedx")                  # rules 10, 11 (0.13.0)
    if not isinstance(d, dict) or d.get("bomFormat") != "CycloneDX":
        raise ValueError("CycloneDX malformed: not a JSON object with bomFormat 'CycloneDX'")
    schema_state, schema_text = cyclonedx_schema_check(d)
    ids = _cdx_identifiers(d)
    seen: Dict[str, int] = {}
    for r in ids:
        seen[r] = seen.get(r, 0) + 1
    repeated = [r for r in dict.fromkeys(ids) if seen[r] > 1]      # document order of the first occurrence
    # rule 5 (spec/SBOM_INGEST.md): 1.4-1.7 "MUST"/"must"/ECMA-424 "shall" be unique -> not conformant; 1.2-1.3 JSON
    # text "should be unique" -> reported only (source.bom_ref_repeated)
    if schema_state == "conformant" and repeated and d.get("specVersion") not in ("1.2", "1.3"):
        dup = repeated[0]
        schema_state = "not_conformant"
        schema_text = (f"not conformant to bom-{d.get('specVersion')} (bom-ref unique within the BOM): "
                       f"{dup[:120]!r} appears {seen[dup]} times")[:300]
    if schema_state == "not_conformant" and not allow_nonconformant:   # rule 1: refused, nothing recorded
        raise ValueError("CycloneDX " + schema_text + " (--allow-nonconformant records it, never as floor met)")
    md = d.get("metadata")
    if isinstance(md, dict) and md.get("component") and not isinstance(md["component"], dict):
        raise ValueError("CycloneDX malformed: 'metadata.component' must be an object")
    gen, gen_ver = _cdx_generator(d)
    # `components` is OPTIONAL in CycloneDX (bom-1.6.schema.json: "required": ["bomFormat", "specVersion"]): a BOM
    # without it (e.g. only metadata.component) is valid and is read as no components, said in source.components_absent
    # (fleet audit 04/11/2026: it was refused as malformed). What is left of the old refusal is the top level of the
    # schemas, _cdx_top_level_valid: `{"bomFormat": "CycloneDX"}` or a misspelled `Components` is not such a BOM and
    # gets no ledger line. Present and not a list is still malformed.
    components_absent = "components" not in d
    if components_absent:
        _cdx_top_level_valid(d)
    items = [] if components_absent else d.get("components")
    if not isinstance(items, list):
        raise ValueError("CycloneDX malformed: 'components' must be a list")
    comps: List[SBOMComponent] = []
    declared, nested, types = 0, 0, {}

    def walk(items: List[Any], level: int) -> None:
        nonlocal declared, nested
        for c in items:
            if not isinstance(c, dict) or not isinstance(c.get("name"), str) or not c["name"]:
                continue                                  # a component whose name is not a string is not a component
            declared += 1
            if level:
                nested += 1
            typ = c.get("type") if isinstance(c.get("type"), str) and c.get("type") else "library"
            types[typ] = types.get(typ, 0) + 1
            sha = ""
            for h in (c.get("hashes") if isinstance(c.get("hashes"), list) else []):
                if isinstance(h, dict) and str(h.get("alg", "")).upper() in ("SHA-256", "SHA256"):
                    sha = _sha256_or_empty(h.get("content", ""))
                    break
            lic = ""
            for le in (c.get("licenses") if isinstance(c.get("licenses"), list) else []):
                if isinstance(le, dict):
                    li = le.get("license") if isinstance(le.get("license"), dict) else {}
                    lic = _s(li.get("id")) or _s(li.get("name")) or _s(le.get("expression"))
                    if lic:
                        break
            sup = c.get("supplier")
            comps.append(SBOMComponent(name=c["name"], version=_s(c.get("version"))[:SCHEMA_TEXT_MAX],
                                       supplier=_s(sup.get("name")) if isinstance(sup, dict) else "",
                                       purl=_s(c.get("purl")), sha256=sha, license=_s(lic)[:512],   # the FIRST licence entry; the document has them all
                                       type=typ if typ in CYCLONEDX_COMPONENT_TYPES else "library", cpe=_s(c.get("cpe"))))
            if isinstance(c.get("components"), list):
                walk(c["components"], level + 1)
    try:
        walk(items, 0)
    except RecursionError:
        raise ValueError("CycloneDX malformed: components nested too deep") from None
    deps = d.get("dependencies") if isinstance(d.get("dependencies"), list) else []
    # CycloneDX 1.6 types a `dependsOn` item as refLinkType: "an element identified by the attribute bom-ref in the
    # SAME BOM document". Counting the edges without resolving them says nothing about whether the graph closes —
    # measured 24/09/2026 on an ORT reporter fixture where 1 of 6 edges pointed at a bom-ref absent from components,
    # and this summary reported 6 edges with no sign of it. Rule 6 (spec/SBOM_INGEST.md): every reference field is
    # resolved against the identifiers of every kind of object (0.12.0 knew only components and metadata.component).
    known_refs = set(ids)
    edges = [t for x in deps if isinstance(x, dict) and isinstance(x.get("dependsOn"), list) for t in x["dependsOn"]]
    unresolved: Dict[str, set] = {}
    for top, fields in (("dependencies", ("ref", "dependsOn", "provides")),
                        ("compositions", ("assemblies", "dependencies", "vulnerabilities"))):
        for x in _lst(d.get(top)):
            for fld in fields if isinstance(x, dict) else ():
                vals = [x.get(fld)] if fld == "ref" else _lst(x.get(fld))
                for t in vals:
                    if isinstance(t, str) and t not in known_refs and not t.startswith("urn:cdx:"):
                        unresolved.setdefault(f"{top}.{fld}", set()).add(t)
    source = {"format": "cyclonedx-json", "spec_version": _s(d.get("specVersion")), "generator": gen, "generator_version": gen_ver,
              "serial_number": _s(d.get("serialNumber")), "components_declared": declared, "components_nested": nested,
              "duplicates_merged": declared - len(dedup(comps)), "dependency_edges": len(edges),
              "dangling_edges": len(unresolved.get("dependencies.dependsOn", ())), "dangling_refs": sorted(set().union(*unresolved.values()))[:10],
              "dangling_by_field": {k: len(v) for k, v in sorted(unresolved.items())},
              "bom_ref_repeated": len(repeated), "bom_ref_repeated_examples": [r[:200] for r in repeated[:3]],
              "dependencies_declared": len(deps), "component_types": dict(sorted(types.items())),
              "schema_check": schema_text}
    if components_absent:
        source["components_absent"] = True
    source.update(_floor_counts(comps))
    source["bsi_tr_03183_2"] = _bsi_tr_note("cyclonedx", _s(d.get("specVersion")))
    source.update(wrapper)
    source.update(_fingerprint_bytes(raw, path))
    md_comp = (d.get("metadata") or {}).get("component") if isinstance(d.get("metadata"), dict) else None
    ptype = _s(md_comp.get("type")) if isinstance(md_comp, dict) else ""
    return SBOMRecord(product_id=product_id, product_version=product_version, components=comps,
                      depth=f"external:cyclonedx:{gen or 'unknown'}", source=source,
                      product_type=ptype if ptype in CYCLONEDX_COMPONENT_TYPES else "application")


# ── SPDX ingest (2.2 / 2.3 JSON and 3.0 JSON-LD) ──────────────────────────────────────────
_NOASSERT = ("", "NOASSERTION", "NONE")


def _clean(v: Any) -> str:
    """A text field: a non-string (list, dict, number, bool) is NOT stringified into the record — it is empty."""
    v = v.strip() if isinstance(v, str) else ""
    return "" if v in _NOASSERT else v


def _agent_name(v: Any) -> str:
    """SPDX 2.x supplier/originator: 'Organization: Acme (mail)' / 'Person: Jane' → the name part (only a
    trailing parenthesised e-mail is dropped, 'Foo (Bar) Ltd' keeps its name)."""
    v = _clean(v)
    for pfx in ("Organization:", "Person:"):
        if v.startswith(pfx):
            v = v[len(pfx):].strip()
    # spec/SBOM_INGEST.md, rules 12 and 13(1): by position, one pass. Until 0.13.0 this was
    # re.sub(r"\s*\([^()]*@[^()]*\)\s*$", "", v), quadratic in len(v) (20/11/2026: 100 kB of "(@@@…x(" took 15 s).
    if v.endswith(")"):
        i = v.rfind("(")
        if i != -1 and "@" in v[i + 1:-1] and ")" not in v[i + 1:-1]:
            v = v[:i].strip()
    return v


def _generator_name_version(text: str) -> Tuple[str, str]:
    """'syft-1.52.0' / 'trivy-0.74.0' → name + version (spec/SBOM_INGEST.md, rules 12 and 13(2)); no version found:
    (text, ""). One pass over the text. Until 0.13.0 this was re.match(r"^(.*?)[-\s]?(\d+\.\d+[\w.\-]*)$", text) with
    group(1).rstrip("-") and group(2): the same result on every input, quadratic in len(text) (20/11/2026: 48 kB of
    "1.11.11.1…!" took 22.7 s)."""
    end = len(text) - 1 if text.endswith("\n") else len(text)     # `$` also matched before a line feed at the very end
    tail = end                                                     # text[tail:end]: only letters, digits, "_", ".", "-"
    while tail > 0 and (text[tail - 1].isalnum() or text[tail - 1] in "_.-"):
        tail -= 1
    i, start = tail, -1
    while i < end:                                                 # the first "digits . digit" inside that tail
        run = i
        while run < end and text[run].isdecimal():
            run += 1
        if run > i and run + 1 < end and text[run] == "." and text[run + 1].isdecimal():
            start = i
            break
        i = max(run, i + 1)                                        # every digit of a run ends at the same place
    if start == -1:
        return text, ""
    cut = start - 1 if start > 0 and text[start - 1].isspace() else start      # (a "-" there goes with the rstrip below)
    if "\n" in text[:cut]:
        return text, ""
    return text[:cut].rstrip("-"), text[start:end]


def _sha256_or_empty(v: Any) -> str:
    v = str(v or "").strip().lower()
    return v if re.fullmatch(r"[0-9a-f]{64}", v) else ""       # a malformed checksum is not evidence


def _ld_type(e: Dict[str, Any]) -> str:
    """JSON-LD type in compact (`type`, `software_Package`) or expanded (`@type`, full IRI) form → short name."""
    t = e.get("type", e.get("@type", ""))
    t = t[0] if isinstance(t, list) and t else t
    t = str(t or "")
    return t.rsplit("/", 1)[-1].rsplit("#", 1)[-1]


def _ld_id(e: Dict[str, Any]) -> str:
    v = e.get("spdxId") or e.get("@id") or ""
    return v if isinstance(v, str) else ""


def _ld_prop(e: Dict[str, Any], *names: str) -> Any:
    """A property by its compact name or by any expanded IRI ending with it."""
    for n in names:
        if n in e:
            return e[n]
    for k, v in e.items():
        tail = k.rsplit("/", 1)[-1].rsplit("#", 1)[-1]
        if tail in names or tail.split("_", 1)[-1] in names:
            return v
    return None


# SPDX 2.3 primaryPackagePurpose → CycloneDX component type (purposes without a counterpart stay "library")
SPDX_PURPOSE_TO_TYPE = {"APPLICATION": "application", "FRAMEWORK": "framework", "LIBRARY": "library", "CONTAINER": "container",
                        "OPERATING-SYSTEM": "operating-system", "DEVICE": "device", "FIRMWARE": "firmware", "FILE": "file"}


def _lst(v: Any) -> List[Any]:
    """A field that must be a JSON array: anything else (5, "x", {}) is read as empty — third-party input, never a crash."""
    return v if isinstance(v, list) else []


def _spdx2_components(d: Dict[str, Any]) -> Tuple[List[SBOMComponent], str, str]:
    rels = [r for r in _lst(d.get("relationships")) if isinstance(r, dict)]
    roots = {r.get("relatedSpdxElement") for r in rels if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT" and isinstance(r.get("relatedSpdxElement"), str)}
    roots |= {r.get("spdxElementId") for r in rels if r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == "SPDXRef-DOCUMENT" and isinstance(r.get("spdxElementId"), str)}
    roots |= {x for x in _lst(d.get("documentDescribes")) if isinstance(x, str)}
    comps = []
    root_purpose = ""
    for p in _lst(d.get("packages")):
        if not isinstance(p, dict) or not _clean(p.get("name")):
            continue                                     # counted by the caller as packages_unnamed
        sid = p.get("SPDXID")
        if isinstance(sid, str) and sid in roots:
            root_purpose = root_purpose or _s(p.get("primaryPackagePurpose")).upper()   # the product's declared purpose → metadata.component.type
            continue                                     # the product itself is metadata, not a dependency
        refs = [r for r in _lst(p.get("externalRefs")) if isinstance(r, dict)]
        purl = next((r.get("referenceLocator", "") for r in refs if r.get("referenceType") == "purl"), "")
        cpe = next((r.get("referenceLocator", "") for r in refs if str(r.get("referenceType", "")).startswith("cpe2")), "")
        sha = next((c.get("checksumValue", "") for c in _lst(p.get("checksums"))
                    if isinstance(c, dict) and str(c.get("algorithm", "")).upper() == "SHA256"), "")
        lic = _clean(p.get("licenseConcluded")) or _clean(p.get("licenseDeclared"))
        comps.append(SBOMComponent(name=_clean(p["name"]), version=_clean(p.get("versionInfo"))[:SCHEMA_TEXT_MAX] or "NOASSERTION",
                                   supplier=_agent_name(p.get("supplier")) or _agent_name(p.get("originator")),   # cleaned BEFORE the fallback
                                   purl=_clean(purl), sha256=_sha256_or_empty(sha), license=lic,
                                   type=SPDX_PURPOSE_TO_TYPE.get(str(p.get("primaryPackagePurpose", "")).upper(), "library"), cpe=_clean(cpe)))
    ci = d.get("creationInfo") if isinstance(d.get("creationInfo"), dict) else {}
    creators = ci.get("creators") if isinstance(ci.get("creators"), list) else []
    tool = next((c for c in creators if str(c).startswith("Tool:")), "")
    depth = f"external:{_clean(d.get('spdxVersion')) or 'SPDX-2.x'}:{_agent_name(tool.replace('Tool:', '')) or 'unknown-tool'}"
    if not roots:
        depth += ":no-root-declared"   # the document names no described product: it may be counted among the components (declared)
    return comps, depth, root_purpose


def _spdx3_components(d: Dict[str, Any]) -> Tuple[List[SBOMComponent], str, str]:
    g = [e for e in _lst(d.get("@graph")) if isinstance(e, dict)]
    known = {"software_Package", "Package", "Relationship", "LifecycleScopedRelationship", "SpdxDocument", "software_Sbom", "Sbom",
             "software_File", "File", "CreationInfo", "Tool", "Organization", "Person", "Agent", "simplelicensing_LicenseExpression", "LicenseExpression"}
    if not any(_ld_type(e) in known for e in g):
        raise ValueError("@graph holds no SPDX 3.0 element (no Package/Sbom/SpdxDocument/Relationship): not an SPDX 3.0 document")
    by_id = {_ld_id(e): e for e in g if _ld_id(e)}
    def _strs(x: Any) -> List[str]:                   # an id reference must be a string; a list of them is allowed; anything else is ignored
        return [y for y in (x if isinstance(x, list) else [x]) if isinstance(y, str)]
    roots = set()
    lic_of: Dict[str, str] = {}

    def _lic_expr(x: Any) -> str:
        le = by_id.get(x) or {}
        expr = _clean(_ld_prop(le, "simplelicensing_licenseExpression", "licenseExpression") or le.get("name"))
        if not expr and isinstance(x, str):
            if x.rstrip("/").endswith(("NoAssertionElement", "NoneElement", "NoAssertionLicense", "NoneLicense")):
                return ""
            if x.startswith("https://spdx.org/licenses/"):          # ListedLicense IRI not embedded in the graph
                expr = x.rsplit("/", 1)[-1]
        return expr
    for e in g:
        t = _ld_type(e)
        if t in ("SpdxDocument", "software_Sbom", "Sbom"):
            roots |= set(_strs(_ld_prop(e, "rootElement")))          # the canonical root marker in SPDX 3.0
        if t in ("Relationship", "LifecycleScopedRelationship"):
            rt = _ld_prop(e, "relationshipType")
            tos = _strs(_ld_prop(e, "to"))
            frm = _ld_prop(e, "from")
            frm = frm if isinstance(frm, str) else ""
            if rt == "describes":
                roots |= set(tos)
            if rt in ("hasConcludedLicense", "hasDeclaredLicense") and frm:
                for x in tos:
                    expr = _lic_expr(x)
                    if expr and (rt == "hasConcludedLicense" or frm not in lic_of):
                        lic_of[frm] = expr
    comps = []
    root_purpose = ""
    for e in g:
        if _ld_type(e) in ("software_Package", "Package") and _ld_id(e) in roots and not root_purpose:
            rp = _ld_prop(e, "software_primaryPurpose", "primaryPurpose")
            rp = rp[0] if isinstance(rp, list) and rp else rp
            root_purpose = _s(rp).rsplit("/", 1)[-1].upper().replace("OPERATINGSYSTEM", "OPERATING-SYSTEM")
        if _ld_type(e) not in ("software_Package", "Package") or not _clean(e.get("name")) or _ld_id(e) in roots:
            continue
        sha = next((h.get("hashValue", "") for h in _lst(_ld_prop(e, "verifiedUsing"))
                    if isinstance(h, dict) and _ld_type(h) == "Hash" and str(h.get("algorithm", "")).lower().rsplit("/", 1)[-1] == "sha256"), "")
        sup = _ld_prop(e, "suppliedBy")
        sup = sup[0] if isinstance(sup, list) and sup else sup
        supplier = _clean((by_id.get(sup) or {}).get("name")) if isinstance(sup, str) else ""
        if not supplier:
            orig = _ld_prop(e, "originatedBy"); orig = orig[0] if isinstance(orig, list) and orig else orig
            supplier = _clean((by_id.get(orig) or {}).get("name")) if isinstance(orig, str) else ""
        purpose = _ld_prop(e, "software_primaryPurpose", "primaryPurpose")
        purpose = str(purpose[0] if isinstance(purpose, list) and purpose else purpose or "").rsplit("/", 1)[-1].upper().replace("OPERATINGSYSTEM", "OPERATING-SYSTEM")
        ext = _lst(_ld_prop(e, "externalIdentifier"))
        cpe = next((_clean(x.get("identifier")) for x in ext if isinstance(x, dict) and str(_ld_prop(x, "externalIdentifierType") or "").rsplit("/", 1)[-1] in ("cpe22", "cpe23")), "")
        comps.append(SBOMComponent(name=_clean(e["name"]), version=_clean(_ld_prop(e, "software_packageVersion", "packageVersion"))[:SCHEMA_TEXT_MAX] or "NOASSERTION",
                                   supplier=supplier, purl=_clean(_ld_prop(e, "software_packageUrl", "packageUrl")), sha256=_sha256_or_empty(sha),
                                   license=lic_of.get(_ld_id(e), ""), type=SPDX_PURPOSE_TO_TYPE.get(purpose, "library"), cpe=_clean(cpe)))
    tools = [e.get("name") for e in g if _ld_type(e) == "Tool" and e.get("name")]
    depth = f"external:SPDX-3.0:{_clean(tools[0]) if tools else 'unknown-tool'}"
    if not roots:
        depth += ":no-root-declared"
    return comps, depth, root_purpose


def _spdx2_see_also(d: Dict[str, Any]) -> Dict[str, Any]:
    """SPDX rule 7 (spec/SBOM_INGEST.md): each `hasExtractedLicensingInfos[i].seeAlsos[j]` against the RFC 3986 `URI`
    rule. `not_a_url`: where and what the first value that is not one is ("" when none); `not_web`: how many values are
    URIs whose scheme is not http/https; `examples`: the first three of those, each cut at 200 characters."""
    out: Dict[str, Any] = {"not_a_url": "", "not_web": 0, "examples": []}
    for i, e in enumerate(_lst(d.get("hasExtractedLicensingInfos"))):
        for j, v in enumerate(_lst(e.get("seeAlsos")) if isinstance(e, dict) else []):
            if not isinstance(v, str) or URI.fullmatch(v) is None:
                if not out["not_a_url"]:
                    out["not_a_url"] = f"hasExtractedLicensingInfos/{i}/seeAlsos/{j}: not a URL (RFC 3986 URI): {v!r}"
            elif v.split(":", 1)[0].lower() not in ("http", "https"):
                out["not_web"] += 1
                if len(out["examples"]) < 3:
                    out["examples"].append(v[:200])
    return out


def _spdx2_repeated_ids(d: Dict[str, Any]) -> List[Tuple[str, int]]:
    """SPDX rule 8 (spec/SBOM_INGEST.md, 0.13.0): the SPDXID values (document, packages, files, snippets) that appear
    more than once, in document order of the first occurrence, with their count"""
    ids = [d.get("SPDXID")] + [x.get("SPDXID") for k in ("packages", "files", "snippets") for x in _lst(d.get(k))
                               if isinstance(x, dict)]
    seen: Dict[str, int] = {}
    for v in ids:
        if isinstance(v, str):
            seen[v] = seen.get(v, 0) + 1
    return [(v, n) for v, n in seen.items() if n > 1]


_SPDX_IDSTRING = re.compile(r"SPDXRef-[A-Za-z0-9.\-]+")
_ABSOLUTE_FILE = re.compile(r"[/\\]|[A-Za-z]:[/\\]")


def _spdx2_spec_rules(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    """SPDX rule 9 (spec/SBOM_INGEST.md, 0.13.0): the rules of the SPDX 2.x text the schema does not express that the
    document does not meet, each with its section; reported, never a refusal"""
    ver = _clean(d.get("spdxVersion")) or "SPDX-2.x"
    out: List[Dict[str, Any]] = []

    def add(section: str, rule: str, bad: List[str]) -> None:
        if bad:
            out.append({"section": f"{ver} {section}", "rule": rule, "count": len(bad), "examples": [b[:200] for b in bad[:3]]})
    files = [f for f in _lst(d.get("files")) if isinstance(f, dict)]
    add("§8.1", "a file name is relative to the package root",
        [f["fileName"] for f in files if isinstance(f.get("fileName"), str) and _ABSOLUTE_FILE.match(f["fileName"])])
    add("§8.4", "a file has a SHA1 checksum (cardinality 1..1)",
        [str(f.get("fileName", f.get("SPDXID", ""))) for f in files
         if not any(isinstance(c, dict) and c.get("algorithm") == "SHA1" for c in _lst(f.get("checksums")))])
    pk = [p for p in _lst(d.get("packages")) if isinstance(p, dict)]
    rels = [r for r in _lst(d.get("relationships")) if isinstance(r, dict)]
    describes = (any(r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT" for r in rels)
                 or any(r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == "SPDXRef-DOCUMENT" for r in rels)
                 or bool(_lst(d.get("documentDescribes"))))
    add("§11.1", "DESCRIBES is mandatory when more than one package is present",
        [f"{len(pk)} packages, no DESCRIBES relationship"] if len(pk) > 1 and not describes else [])
    if ver == "SPDX-2.2":     # 2.3: the 2.3.1 schema already refuses it (pattern)
        ids = [d.get("SPDXID")] + [x.get("SPDXID") for k in ("packages", "files", "snippets") for x in _lst(d.get(k))
                                   if isinstance(x, dict)]
        add("§6.3/§7.2/§8.2/§9.1", "SPDXRef-[idstring], idstring letters, numbers, '.' and '-'",
            [v for v in ids if isinstance(v, str) and not _SPDX_IDSTRING.fullmatch(v)])
    return out


def sbom_from_spdx(path: str, product_id: str, product_version: str, raw: Optional[bytes] = None,
                   allow_nonconformant: bool = False) -> SBOMRecord:
    """Ingest an SPDX document: 2.2/2.3 JSON (`spdxVersion`, `packages`, `relationships`; DESCRIBES/DESCRIBED_BY
    /documentDescribes name the product) or 3.0 JSON-LD (`@graph` of Package elements in compact `type`/`spdxId`
    or expanded `@type`/`@id`/IRI form; `rootElement` of the Sbom/SpdxDocument or a `describes` relationship names
    the product; licences via hasConcludedLicense/hasDeclaredLicense to an embedded expression or a ListedLicense
    IRI; supplier via `suppliedBy`, then `originatedBy`). The product is metadata, not a component; when no root
    is declared the depth says `:no-root-declared` (the product may then be counted). Field names checked on the
    official spdx/spdx-examples documents (15/09/2026); other generators' output is parsed by these rules, not
    proven against every tool. A document of neither shape raises."""
    raw, d = _load_document(path, raw)
    d, wrapper = _unwrap(d, "spdx")                       # rules 10, 11 (0.13.0)
    if not isinstance(d, dict):
        raise ValueError("SPDX document is not a JSON object")
    if "spdxVersion" not in d and "@graph" not in d:
        raise ValueError("not an SPDX 2.x JSON (spdxVersion) nor an SPDX 3.0 JSON-LD (@graph) document")
    schema_state, schema_text = spdx_schema_check(d)       # rules 1-3: before anything is read from the document
    spdx2 = str(d.get("spdxVersion", "")).startswith("SPDX-2")
    see_also = _spdx2_see_also(d) if spdx2 else None
    if schema_state == "conformant" and see_also and see_also["not_a_url"]:     # rule 7.1 (spec/SBOM_INGEST.md): §10.4, a URL
        schema_state = "not_conformant"
        schema_text = (f"not conformant to {d['spdxVersion']} §10.4 at {see_also['not_a_url']}")[:300]
    ids_repeated = _spdx2_repeated_ids(d) if spdx2 else []
    if schema_state == "conformant" and ids_repeated:     # rule 8 (0.13.0): §6.3/§7.2/§8.2/§9.1 "a unique string"
        v, n = ids_repeated[0]
        schema_state = "not_conformant"
        schema_text = f"not conformant to {d['spdxVersion']} §7.2 (SPDXID unique): {v[:120]!r} appears {n} times"[:300]
    if schema_state in ("not_conformant", "unsupported") and not allow_nonconformant:
        raise ValueError("SPDX " + schema_text + " (--allow-nonconformant records it, never as floor met)")
    if spdx2:
        comps, depth, root_purpose = _spdx2_components(d)
        pk = [x for x in _lst(d.get("packages")) if isinstance(x, dict)]
        rels = [r for r in _lst(d.get("relationships")) if isinstance(r, dict)]
        source = {"format": "spdx-json", "spec_version": _clean(d.get("spdxVersion")), "packages_declared": len(pk),
                  "packages_unnamed": sum(1 for x in pk if not _clean(x.get("name"))), "relationships_declared": len(rels),
                  "dependency_edges": sum(1 for r in rels if str(r.get("relationshipType", "")).upper() in ("DEPENDS_ON", "DEPENDENCY_OF")),
                  "see_also_not_web": see_also["not_web"], "see_also_not_web_examples": see_also["examples"],
                  "spdxid_repeated": len(ids_repeated), "spdxid_repeated_examples": [v[:200] for v, _ in ids_repeated[:3]],
                  "spec_rules": _spdx2_spec_rules(d)}
    elif "@graph" in d:
        comps, depth, root_purpose = _spdx3_components(d)
        g = [e for e in _lst(d.get("@graph")) if isinstance(e, dict)]
        source = {"format": "spdx-jsonld", "spec_version": "SPDX-3.0",
                  "packages_declared": sum(1 for e in g if _ld_type(e) in ("software_Package", "Package")),
                  "packages_unnamed": sum(1 for e in g if _ld_type(e) in ("software_Package", "Package") and not _clean(e.get("name"))),
                  "relationships_declared": sum(1 for e in g if _ld_type(e) in ("Relationship", "LifecycleScopedRelationship")),
                  "dependency_edges": sum(1 for e in g if _ld_type(e) in ("Relationship", "LifecycleScopedRelationship") and _ld_prop(e, "relationshipType") == "dependsOn")}
    else:
        raise ValueError("not an SPDX 2.x JSON (spdxVersion) nor an SPDX 3.0 JSON-LD (@graph) document")
    parts = depth.split(":")
    source.update({"generator": parts[2] if len(parts) > 2 else "", "generator_version": "",
                   "roots_excluded": source["packages_declared"] - source["packages_unnamed"] - len(comps),
                   "duplicates_merged": len(comps) - len(dedup(comps))})
    source["generator"], source["generator_version"] = _generator_name_version(source["generator"])
    source["schema_check"] = schema_text
    source.update(_floor_counts(comps))
    ctx = d.get("@context")
    source["bsi_tr_03183_2"] = _bsi_tr_note("spdx", _clean(d.get("spdxVersion"))[5:] if spdx2 else   # "SPDX-2.3" -> "2.3"
                                            "3.0.1" if ctx == SPDX3_CONTEXT_301 or (isinstance(ctx, list) and SPDX3_CONTEXT_301 in ctx)
                                            else "0")
    source.update(wrapper)
    source.update(_fingerprint_bytes(raw, path))
    if root_purpose:
        source["root_purpose_declared"] = root_purpose     # kept as declared even when it has no CycloneDX counterpart (Trivy: SOURCE)
    return SBOMRecord(product_id=product_id, product_version=product_version, components=comps, depth=depth, source=source,
                      product_type=SPDX_PURPOSE_TO_TYPE.get(root_purpose, "application"))


def reingest(raw: bytes, path: str, fmt: str, product_id: str, product_version: str) -> SBOMRecord:
    """The same ingest function, on bytes already in hand (the locker re-derives the index from the bytes it stores)."""
    if fmt == "cyclonedx-json":     # the refusal was decided at ingest; here schema_check must come out the same
        return sbom_from_cyclonedx(path, product_id, product_version, raw=raw, allow_nonconformant=True)
    if fmt in ("spdx-json", "spdx-jsonld"):     # likewise
        return sbom_from_spdx(path, product_id, product_version, raw=raw, allow_nonconformant=True)
    raise ValueError(f"unknown source format {fmt!r}")

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roberto Locatelli
"""VEX and other documents attached to a vulnerability record: the declared format is checked (spec/VEX.md, 0.13.0).

Until 0.12.0 an attachment was kept verbatim under whatever label the caller gave. Here each label of
ATTACHMENT_FORMATS has its check; a document that is not of its declared format is refused with the reason
(ValueError), never kept "as declared":

- openvex        `@context` exactly https://openvex.dev/ns/v0.2.0 and the OpenVEX 0.2.0 JSON schema (openvex/spec,
                 CC0-1.0, data/openvex/SOURCES.txt); values that do not meet a `format` are reported, not refused
                 (JSON Schema 2020-12: an annotation);
- cyclonedx-vex  a CycloneDX BOM conformant as `cra sbom` checks it, with a non-empty `vulnerabilities` array;
- cyclonedx-sbom a CycloneDX BOM conformant as `cra sbom` checks it;
- spdx-3.0       an SPDX 3.0.1 JSON-LD document, checked with the official schema;
- csaf-2.0       form only (the five required properties of `document`, CSAF 2.0 §3.2.1): the CSAF schema is not
                 shipped (OASIS IPR policy, no redistribution licence found) and `schema_check` says so.

Nothing here compares a VEX statement with the record's vulnerability id or with the product's SBOM."""
import hashlib
import json
import os
from typing import Any, Dict, Iterator, Optional, Tuple

from . import sbom as _sbom

__all__ = ["ATTACHMENT_FORMATS", "CSAF_FORM_ONLY", "OPENVEX_CONTEXT", "OPENVEX_SCHEMA", "check_attachment", "check_file"]

ATTACHMENT_FORMATS = frozenset({"cyclonedx-vex", "csaf-2.0", "openvex", "cyclonedx-sbom", "spdx-3.0"})
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
OPENVEX_SCHEMA = "openvex_json_schema-0.2.0-93139bd.json"
CSAF_FORM_ONLY = "form only (CSAF 2.0 schema not shipped)"
_OPENVEX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "openvex")
_OPENVEX_FORMATS = ("uri", "iri", "date-time")      # every `format` the OpenVEX 0.2.0 schema uses
_VALIDATOR: Dict[str, Any] = {}


def _openvex_validator() -> Tuple[Any, Any, Optional[str]]:
    """(validator, format validator or None, None) or (None, None, the reason the schema check cannot run). The first
    decides (JSON Schema 2020-12, Validation §7.2.1: `format` is an annotation unless a schema asks for assertion, and
    this schema's dialect does not); the second, the same schema with the formats asserted, is used only to REPORT the
    values that do not meet their format. It is None when the library cannot check every format the schema uses."""
    if "v" in _VALIDATOR:
        return _VALIDATOR["v"], _VALIDATOR["f"], None
    try:
        import jsonschema                  # the extra [schema]
    except ImportError as e:
        return None, None, f"jsonschema is not installed ({e}); install omega-cra-evol[schema]"
    cls = getattr(jsonschema, "Draft202012Validator", None)
    if cls is None:
        return None, None, "jsonschema too old (no Draft202012Validator); install omega-cra-evol[schema]"
    with open(os.path.join(_OPENVEX_DIR, OPENVEX_SCHEMA), "rb") as fh:
        doc = json.loads(fh.read().decode("utf-8"))
    cls.check_schema(doc)
    known = set(_formats_used(doc)) <= set(_OPENVEX_FORMATS) and all(f in cls.FORMAT_CHECKER.checkers for f in _OPENVEX_FORMATS)
    _VALIDATOR["v"], _VALIDATOR["f"] = cls(doc), (cls(doc, format_checker=cls.FORMAT_CHECKER) if known else None)
    return _VALIDATOR["v"], _VALIDATOR["f"], None


def _formats_used(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        if isinstance(node.get("format"), str):
            yield node["format"]
        for v in node.values():
            yield from _formats_used(v)
    elif isinstance(node, list):
        for v in node:
            yield from _formats_used(v)


def _refuse(why: str) -> "ValueError":
    return ValueError(" ".join(str(why).split())[:400])


def _openvex(doc: Dict[str, Any]) -> Dict[str, Any]:
    ctx = doc.get("@context")
    if ctx != OPENVEX_CONTEXT:
        if isinstance(ctx, str) and (ctx == "https://openvex.dev/ns" or ctx.startswith("https://openvex.dev/ns/")):
            raise _refuse(f"OpenVEX @context {ctx[:80]!r}: only {OPENVEX_CONTEXT} is read "
                          "(without a version the specification means v0.0.1)")
        raise _refuse(f"not an OpenVEX document: @context is {json.dumps(ctx)[:120]}, not {OPENVEX_CONTEXT!r}")
    st = doc.get("statements")
    if not isinstance(st, list):
        raise _refuse("OpenVEX: statements is not an array")
    v, vf, why = _openvex_validator()
    if v is None:
        return {"schema_check": "not checked: " + why, "statements": len(st)}
    from jsonschema.exceptions import best_match
    from .canonical import deep_recursion
    try:
        with deep_recursion():
            err = best_match(v.iter_errors(doc))
            fmt = [e for e in vf.iter_errors(doc) if e.validator == "format"] if (err is None and vf is not None) else []
    except RecursionError:
        raise _refuse("OpenVEX malformed: nested too deep for the schema check") from None
    if err is not None:
        where = "/".join(str(x) for x in err.absolute_path) or "(document)"
        raise _refuse(f"OpenVEX not conformant to {OPENVEX_SCHEMA} at {where}: {err.message}")
    out = {"schema_check": f"conformant to {OPENVEX_SCHEMA}", "statements": len(st)}
    if vf is None:
        out["format_not_met"] = "not checked: jsonschema cannot check every format of the schema (install omega-cra-evol[schema])"
    else:      # reported, not refused: uri, iri and date-time values that are not what the schema annotates them as
        out["format_not_met"] = len(fmt)
        out["format_not_met_examples"] = [("/".join(str(x) for x in e.absolute_path) + ": " + e.message)[:200] for e in fmt[:3]]
    return out


def _raw(doc: Dict[str, Any]) -> bytes:
    try:
        return json.dumps(doc, ensure_ascii=False).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as e:
        raise _refuse(f"document cannot be serialised as JSON ({type(e).__name__})") from None


def _cyclonedx(doc: Dict[str, Any], vex: bool) -> Dict[str, Any]:
    if doc.get("bomFormat") != "CycloneDX":
        raise _refuse("not a CycloneDX document: bomFormat is not 'CycloneDX'")
    vulns = doc.get("vulnerabilities")
    if vex and not (isinstance(vulns, list) and vulns):
        raise _refuse("CycloneDX VEX: no vulnerabilities (a non-empty `vulnerabilities` array is what makes a BOM a VEX)")
    rec = _sbom.sbom_from_cyclonedx("attachment.json", "-", "-", raw=_raw(doc))    # rules 1-5; refuses with the reason
    out = {"schema_check": rec.source["schema_check"], "spec_version": rec.source.get("spec_version", "")}
    if isinstance(vulns, list):
        out["vulnerabilities"] = len(vulns)
    return out


def _spdx3(doc: Dict[str, Any]) -> Dict[str, Any]:
    if "spdxVersion" in doc or "@graph" not in doc:
        raise _refuse("not an SPDX 3.0 JSON-LD document (no @graph)")
    state, text = _sbom.spdx_schema_check(doc)
    if state in ("not_conformant", "unsupported"):
        raise _refuse("SPDX " + text)
    return {"schema_check": text, "elements": len(doc["@graph"]) if isinstance(doc["@graph"], list) else 0}


def _csaf(doc: Dict[str, Any]) -> Dict[str, Any]:
    d = doc.get("document")
    if not isinstance(d, dict):
        raise _refuse("not a CSAF document: `document` is not an object")
    ver = d.get("csaf_version")
    if ver != "2.0":
        raise _refuse(f"CSAF: document.csaf_version is {json.dumps(ver)[:40]}, not \"2.0\" (the only version read)")
    for k, t, name in (("category", str, "a string"), ("title", str, "a string"), ("publisher", dict, "an object"),
                       ("tracking", dict, "an object")):
        if not isinstance(d.get(k), t) or (t is str and not d[k]):
            raise _refuse(f"CSAF 2.0 §3.2.1: document.{k} is not {name}")
    out: Dict[str, Any] = {"schema_check": CSAF_FORM_ONLY, "category": d["category"][:80]}
    if isinstance(doc.get("vulnerabilities"), list):
        out["vulnerabilities"] = len(doc["vulnerabilities"])
    return out


def check_attachment(fmt: Any, doc: Any) -> Dict[str, Any]:
    """Check `doc` (a JSON object) as a document of the declared format `fmt`. Returns {"format", "schema_check", …
    counts}; raises ValueError with the reason when the label is unknown, the document is not an object, or it is not
    a document of that format. `schema_check` is `conformant to <schema file>`, `not checked: <why>` (jsonschema not
    installed: only the form was checked) or, for CSAF, CSAF_FORM_ONLY."""
    if not isinstance(fmt, str) or fmt not in ATTACHMENT_FORMATS:
        raise _refuse(f"format must be one of {sorted(ATTACHMENT_FORMATS)}, not {str(fmt)[:40]!r}")
    if not isinstance(doc, dict):
        raise _refuse(f"{fmt}: the document is not a JSON object")
    if fmt == "openvex":
        out = _openvex(doc)
    elif fmt in ("cyclonedx-vex", "cyclonedx-sbom"):
        try:
            out = _cyclonedx(doc, fmt == "cyclonedx-vex")
        except ValueError as e:
            raise _refuse(str(e).replace(" (--allow-nonconformant records it, never as floor met)", "")) from None
    elif fmt == "spdx-3.0":
        out = _spdx3(doc)
    else:
        out = _csaf(doc)
    return {"format": fmt, **out}


def check_file(path: str, fmt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Read one file once (bounded and parsed as an SBOM source: a duplicate key, invalid UTF-8 or a nesting the parser
    cannot read is a malformed document) and check it as `fmt`. Returns (result with the file's sha256, the document)."""
    if fmt not in ATTACHMENT_FORMATS:
        raise _refuse(f"format must be one of {sorted(ATTACHMENT_FORMATS)}, not {str(fmt)[:40]!r}")
    raw, doc = _sbom._load_document(path)
    r = check_attachment(fmt, doc)
    r["sha256"] = hashlib.sha256(raw).hexdigest()
    return r, doc

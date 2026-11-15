# SPDX-License-Identifier: AGPL-3.0-or-later
"""Measure the public surface of a Python package with `ast` only (standard library, nothing is imported or run).

  python3 api_surface.py measure  PKGDIR   # counts per module (JSON on stdout)
  python3 api_surface.py holes    PKGDIR   # every signature with a missing annotation, one per line
  python3 api_surface.py all      PKGDIR   # the literal __all__ proposed for each module
  python3 api_surface.py snapshot PKGDIR   # the declared interface (names in __all__, with signatures), as text
  python3 api_surface.py check    PKGDIR   # exit 1 if a module has no literal __all__ or a wrong one

What "public" means here, before `__all__` exists: a module-level name that does not start with an underscore and
is DEFINED in the module (def, class, assignment); imported names are not counted (typing spec, "Imported symbols
are considered private by default"). Once a module has a literal `__all__`, `snapshot` reads that and nothing else
(typing spec: `__all__` overrides all other rules).

What a "hole" is: a parameter without annotation (self/cls excepted) or a missing return annotation
(`__init__` excepted when at least one parameter is annotated — the rule mypy applies). These are the definitions
`mypy --disallow-untyped-defs` / `--disallow-incomplete-defs` would report; this script is NOT a type checker: it
sees that an annotation is there, not that it is right.
"""
from __future__ import annotations

import ast
import json
import os
import sys
from typing import Any, Dict, Iterator, List, Optional, Tuple

BARE_GENERICS = {"dict", "list", "set", "frozenset", "tuple", "Dict", "List", "Set", "FrozenSet", "Tuple", "Callable",
                 "Iterator", "Iterable", "Sequence", "Mapping", "Type", "type"}


def modules(pkgdir: str) -> List[Tuple[str, str]]:
    """(module name, path) of every .py directly in pkgdir, sorted"""
    out = []
    for f in sorted(os.listdir(pkgdir)):
        if f.endswith(".py"):
            out.append((f[:-3], os.path.join(pkgdir, f)))
    return out


def parse(path: str) -> ast.Module:
    with open(path, encoding="utf-8") as f:
        return ast.parse(f.read(), filename=path)


def literal_all(tree: ast.Module) -> Optional[List[str]]:
    """the names of a literal `__all__ = [...]` / `(...)`, or None when the module has none (or a computed one)"""
    for node in tree.body:
        targets: List[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
            value: Optional[ast.expr] = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
            if isinstance(value, (ast.List, ast.Tuple)) and all(
                    isinstance(e, ast.Constant) and isinstance(e.value, str) for e in value.elts):
                return [e.value for e in value.elts]  # type: ignore[attr-defined]
            return None
    return None


def has_all(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            return True
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "__all__":
            return True
    return False


def _top_statements(tree: ast.Module) -> Iterator[ast.stmt]:
    """module-level statements, also those under a module-level `if` / `try` (optional-dependency blocks)"""
    stack = list(reversed(tree.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, ast.If):
            stack.extend(reversed(node.body + node.orelse))
        elif isinstance(node, ast.Try):
            inner = node.body + node.orelse + node.finalbody
            for h in node.handlers:
                inner = inner + h.body
            stack.extend(reversed(inner))


def defined_names(tree: ast.Module) -> Dict[str, str]:
    """module-level name -> kind ("def", "class", "const"), for names DEFINED here (not imported); first wins"""
    out: Dict[str, str] = {}
    for node in _top_statements(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, "def")
        elif isinstance(node, ast.ClassDef):
            out.setdefault(node.name, "class")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                for n in ([t] if isinstance(t, ast.Name) else list(getattr(t, "elts", []))):
                    if isinstance(n, ast.Name):
                        out.setdefault(n.id, "const")
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.setdefault(node.target.id, "const")
    return out


def imported_names(tree: ast.Module) -> List[str]:
    """names bound at module level by an import (the ones a `py.typed` reader treats as private unless re-exported)"""
    out = []
    for node in _top_statements(tree):
        if isinstance(node, ast.Import):
            out += [(a.asname or a.name.split(".")[0]) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            out += [(a.asname or a.name) for a in node.names]
    return out


def public(name: str) -> bool:
    return not name.startswith("_")


def proposed_all(tree: ast.Module) -> List[str]:
    """public names defined in the module, in order of definition kind then name (stable, hand-reviewable)"""
    d = defined_names(tree)
    return sorted(n for n in d if public(n) and n != "annotations")


def _holes_of(fn: ast.AST, in_class: bool) -> List[str]:
    assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
    a = fn.args
    params = list(a.posonlyargs) + list(a.args)
    static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.decorator_list)
    if in_class and not static and params:
        params = params[1:]                                  # self / cls
    params += list(a.kwonlyargs)
    if a.vararg:
        params.append(a.vararg)
    if a.kwarg:
        params.append(a.kwarg)
    missing = [p.arg for p in params if p.annotation is None]
    annotated = len(params) - len(missing)
    if fn.returns is None and not (fn.name == "__init__" and annotated > 0):
        missing.append("return")
    return missing


def _bare_generics(fn: ast.AST) -> List[str]:
    """annotations that are a bare generic name (`dict`, `List`, `Callable`…): what --disallow-any-generics reports"""
    assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
    out = []
    a = fn.args
    anns = [p.annotation for p in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs) + [a.vararg, a.kwarg] if p is not None]
    anns.append(fn.returns)
    for ann in anns:
        if ann is None:
            continue
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):     # a quoted annotation
            try:
                ann = ast.parse(ann.value, mode="eval").body
            except SyntaxError:
                continue
        subscripted = {id(n.value) for n in ast.walk(ann) if isinstance(n, ast.Subscript)}
        for n in ast.walk(ann):
            if isinstance(n, ast.Name) and n.id in BARE_GENERICS and id(n) not in subscripted:
                out.append(n.id)
    return out


def functions(tree: ast.Module) -> Iterator[Tuple[str, ast.AST, bool, bool]]:
    """(qualified name, node, in_class, is_public) for module-level functions and the methods of module-level
    classes; nested functions and lambdas are not listed (mypy checks them, an interface does not contain them)"""
    for node in _top_statements(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node, False, public(node.name)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    dunder = sub.name.startswith("__") and sub.name.endswith("__")
                    yield f"{node.name}.{sub.name}", sub, True, public(node.name) and (public(sub.name) or dunder)


def nested_functions(tree: ast.Module) -> int:
    top = {id(n) for _, n, _, _ in functions(tree)}
    return sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(n) not in top)


def holes(tree: ast.Module) -> List[Tuple[str, int, bool, List[str]]]:
    """(qualified name, line, is_public, missing) for every listed function with at least one missing annotation"""
    out = []
    for q, fn, in_class, pub in functions(tree):
        m = _holes_of(fn, in_class)
        if m:
            out.append((q, fn.lineno, pub, m))                               # type: ignore[attr-defined]
    return out


def count_name(tree: ast.Module, name: str) -> int:
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == name)


def type_ignores(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if "# type: ignore" in line)


def measure(pkgdir: str) -> Dict[str, Any]:
    per: Dict[str, Any] = {}
    for name, path in modules(pkgdir):
        tree = parse(path)
        d = defined_names(tree)
        fns = list(functions(tree))
        hs = holes(tree)
        per[name] = {
            "has___all__": has_all(tree),
            "literal___all__": literal_all(tree) is not None,
            "public_defined": {k: sum(1 for n, kind in d.items() if public(n) and kind == k) for k in ("def", "class", "const")},
            "private_defined": sum(1 for n in d if not public(n)),
            "imported_names": len(imported_names(tree)),
            "functions_listed": len(fns),
            "functions_public": sum(1 for _, _, _, pub in fns if pub),
            "holes_public": sum(1 for _, _, pub, _ in hs if pub),
            "holes_private": sum(1 for _, _, pub, _ in hs if not pub),
            "nested_functions_not_listed": nested_functions(tree),
            "bare_generics_in_signatures": sum(len(_bare_generics(fn)) for _, fn, _, _ in fns),
            "Any_names": count_name(tree, "Any"),
            "type_ignore_comments": type_ignores(path),
        }
    tot: Dict[str, Any] = {}
    for m in per.values():
        for k, v in m.items():
            if isinstance(v, bool):
                tot[k] = tot.get(k, 0) + int(v)
            elif isinstance(v, int):
                tot[k] = tot.get(k, 0) + v
            else:
                for kk, vv in v.items():
                    tot[k + "." + kk] = tot.get(k + "." + kk, 0) + vv
    return {"package": os.path.basename(os.path.normpath(pkgdir)), "modules": len(per), "total": tot, "per_module": per}


def _sig(fn: ast.AST) -> str:
    assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
    return f"({ast.unparse(fn.args)})" + (f" -> {ast.unparse(fn.returns)}" if fn.returns is not None else "")


def snapshot(pkgdir: str) -> str:
    """The declared interface as text: for every module with a literal `__all__`, each name with its kind and, for
    functions and for the public methods of classes, its signature. A module without a literal `__all__` is one line
    saying so. Deterministic: sorted, no line numbers, no values of constants."""
    lines: List[str] = []
    for name, path in modules(pkgdir):
        tree = parse(path)
        names = literal_all(tree)
        if names is None:
            lines.append(f"{name}: NO LITERAL __all__")
            continue
        d = defined_names(tree)
        imp = set(imported_names(tree))
        nodes = {n.name: n for n in _top_statements(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        for n in sorted(names):
            if n in nodes and isinstance(nodes[n], ast.ClassDef):
                cls = nodes[n]
                bases = ", ".join(ast.unparse(b) for b in cls.bases)             # type: ignore[attr-defined]
                lines.append(f"{name}.{n}: class({bases})")
                for sub in cls.body:                                             # type: ignore[attr-defined]
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if public(sub.name) or (sub.name.startswith("__") and sub.name.endswith("__")):
                            lines.append(f"{name}.{n}.{sub.name}{_sig(sub)}")
                    elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name) and public(sub.target.id):
                        lines.append(f"{name}.{n}.{sub.target.id}: {ast.unparse(sub.annotation)}")
            elif n in nodes:
                lines.append(f"{name}.{n}{_sig(nodes[n])}")
            elif n in d:
                lines.append(f"{name}.{n}: const")
            elif n in imp:
                lines.append(f"{name}.{n}: re-export")
            else:
                lines.append(f"{name}.{n}: NOT DEFINED IN MODULE")
    return "\n".join(lines) + "\n"


def all_problems(pkgdir: str) -> List[str]:
    """what makes an `__all__` wrong: a module without a literal one, a listed name that the module neither defines
    nor imports, a private name listed, a duplicate, a list not sorted (so that a diff is one line)"""
    out = []
    for name, path in modules(pkgdir):
        tree = parse(path)
        names = literal_all(tree)
        if names is None:
            out.append(f"{name}: no literal __all__")
            continue
        known = set(defined_names(tree)) | set(imported_names(tree))
        for n in names:
            if n not in known:
                out.append(f"{name}: __all__ names {n!r}, which the module neither defines nor imports")
            if not public(n) and n != "__version__":
                out.append(f"{name}: __all__ names the private {n!r}")
        if len(set(names)) != len(names):
            out.append(f"{name}: duplicate in __all__")
        if names != sorted(names):
            out.append(f"{name}: __all__ is not sorted")
    return out


def main(argv: List[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("measure", "holes", "all", "snapshot", "check"):
        sys.stderr.write(__doc__ or "")
        return 2
    cmd, pkgdir = argv[1], argv[2]
    if not os.path.isdir(pkgdir):
        sys.stderr.write(f"not a directory: {pkgdir}\n")
        return 2
    if cmd == "measure":
        print(json.dumps(measure(pkgdir), indent=1, sort_keys=True))
    elif cmd == "holes":
        n = 0
        for name, path in modules(pkgdir):
            for q, line, pub, missing in holes(parse(path)):
                print(f"{'public ' if pub else 'private'} {name}.py:{line} {q} missing: {', '.join(missing)}")
                n += 1
        print(f"{n} signatures with a missing annotation")
    elif cmd == "all":
        for name, path in modules(pkgdir):
            print(f"{name}: __all__ = {json.dumps(proposed_all(parse(path)))}")
    elif cmd == "snapshot":
        sys.stdout.write(snapshot(pkgdir))
    else:
        problems = all_problems(pkgdir)
        for p in problems:
            print(p)
        print(f"{len(problems)} problem(s)")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Python 3.9 syntax-safety guard for SHIPPED runtime files.

Two independent 3.10+/3.11+ syntax traps live here because they share one root
cause and one scope: source that the newer test-venv interpreter accepts but
the bundled Python 3.9 rejects (or mis-evaluates) at import, crashing the app
at launch. The first is PEP 604 union annotations; the second is possessive
quantifiers / atomic groups in regex literals (see the second section below).

Why this exists
---------------
The built .app bundles the system's universal2 ``/usr/bin/python3`` (3.9 on
current macOS installers). Python 3.9 evaluates most annotations *at import
time*. A PEP 604 union written as ``int | None`` (rather than
``typing.Optional[int]``) is a real ``BinOp`` that 3.9 tries to evaluate ->
``TypeError: unsupported operand type(s) for |`` -> the module fails to import
-> the whole app dies at launch. This is exactly how a real py2app launch
crashed on ``app_entrypoint.py`` line 193 (``_FILTER_LOCK_FD: int | None``).

The test suite normally runs under a newer Python that accepts ``int | None``
everywhere, so nothing catches this. This test closes that gap by scanning the
source with the ``ast`` module (Python-version independent) and enforcing the
codebase idiom: any shipped file that uses modern (3.10+) annotation syntax
MUST carry ``from __future__ import annotations``, which turns every annotation
into an un-evaluated string and makes the syntax 3.9-safe.

What is flagged (only in files that LACK the future import)
-----------------------------------------------------------
1. PEP 604 unions (``X | Y``) in any annotation position -- module/class/local
   variable annotations and function argument/return annotations. Inside an
   annotation, a ``BinOp`` with a ``BitOr`` operator is unambiguously a type
   union (never a bitwise int op), so this cannot false-positive on things like
   ``os.O_CREAT | os.O_RDWR``.
2. Subscripted builtin generics (``list[str]``, ``dict[str, int]``, ...) that
   appear OUTSIDE annotation positions -- e.g. a module-level type alias
   ``Foo = dict[str, int]`` or ``isinstance(x, list[str])``. Those are evaluated
   on 3.9 regardless of the future import and raise ``TypeError``. We do NOT
   flag subscripted builtins *inside* annotations (legitimate and common) and
   we do NOT flag ``X | Y`` outside annotations (there it is usually a genuine
   bitwise/set operation that must run on 3.9).

Scope: shipped runtime files only. ``tests/`` and ``tools/`` are intentionally
excluded -- they only ever run under the dev interpreter, never inside the
bundled 3.9 app.
"""
from __future__ import annotations

import ast
import glob
import os

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Builtin generic types whose subscription (list[str], dict[...], ...) is a
# runtime TypeError on Python 3.9 when evaluated outside an annotation.
BUILTIN_GENERICS = {"list", "dict", "set", "tuple", "frozenset", "type"}

# Glob patterns for every .py file that ships inside MailWarden.app / the
# self-installed ~/MailWarden runtime and therefore executes under the bundled
# Python 3.9. app/resources/launcher.py is included defensively (it does not
# exist today; the glob simply yields nothing if so).
SHIPPED_PATTERNS = (
    "app/mailwarden_app/*.py",
    "app/setup_app.py",
    "payload/MailWarden/src/*.py",
    "app/resources/launcher.py",
)


def _shipped_files() -> list[str]:
    files: list[str] = []
    for pattern in SHIPPED_PATTERNS:
        files.extend(glob.glob(os.path.join(REPO_ROOT, pattern)))
    return sorted(set(files))


def _has_future_annotations(tree: ast.Module) -> bool:
    """True if the module declares ``from __future__ import annotations``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            if any(alias.name == "annotations" for alias in node.names):
                return True
    return False


def _annotation_nodes(tree: ast.Module) -> list[ast.AST]:
    """Every AST subtree that sits in a real annotation position."""
    anns: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            anns.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
                if arg.annotation is not None:
                    anns.append(arg.annotation)
            if a.vararg is not None and a.vararg.annotation is not None:
                anns.append(a.vararg.annotation)
            if a.kwarg is not None and a.kwarg.annotation is not None:
                anns.append(a.kwarg.annotation)
            if node.returns is not None:
                anns.append(node.returns)
    return anns


def _union_hits_in_annotations(tree: ast.Module) -> list[int]:
    """Line numbers of PEP 604 unions (X | Y) inside annotation positions."""
    hits: list[int] = []
    for ann in _annotation_nodes(tree):
        for node in ast.walk(ann):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                hits.append(getattr(node, "lineno", getattr(ann, "lineno", 0)))
    return sorted(hits)


def _subscripted_builtin_hits_outside_annotations(tree: ast.Module) -> list[tuple[int, str]]:
    """(line, name) for builtin-generic subscriptions outside annotations."""
    annotation_node_ids: set[int] = set()
    for ann in _annotation_nodes(tree):
        for node in ast.walk(ann):
            annotation_node_ids.add(id(node))

    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and id(node) not in annotation_node_ids:
            value = node.value
            if isinstance(value, ast.Name) and value.id in BUILTIN_GENERICS:
                hits.append((node.lineno, value.id))
    return sorted(hits)


def _parse(path: str) -> ast.Module:
    with open(path, encoding="utf-8") as fh:
        return ast.parse(fh.read(), filename=path)


@pytest.mark.parametrize("path", _shipped_files(), ids=lambda p: os.path.relpath(p, REPO_ROOT))
def test_shipped_file_is_py39_annotation_safe(path: str) -> None:
    """No shipped file may crash on Python 3.9's runtime annotation evaluation."""
    tree = _parse(path)
    rel = os.path.relpath(path, REPO_ROOT)

    # Files that carry the future import turn all annotations into strings, so
    # any modern annotation syntax inside them is 3.9-safe by construction.
    if _has_future_annotations(tree):
        return

    union_hits = _union_hits_in_annotations(tree)
    subscript_hits = _subscripted_builtin_hits_outside_annotations(tree)

    problems: list[str] = []
    if union_hits:
        problems.append(
            "PEP 604 unions (X | Y) in annotation positions at line(s) "
            f"{union_hits}"
        )
    if subscript_hits:
        problems.append(
            "subscripted builtin generics outside annotations at "
            + ", ".join(f"line {ln}: {name}[...]" for ln, name in subscript_hits)
        )

    assert not problems, (
        f"{rel} uses Python 3.10+ syntax that Python 3.9 evaluates at import "
        f"time (the bundled interpreter), but lacks "
        f"'from __future__ import annotations'. This crashes the app at launch. "
        f"Fix: add 'from __future__ import annotations' immediately after the "
        f"module docstring, OR use typing.Optional/typing.List instead. "
        f"Details: {'; '.join(problems)}"
    )


def test_guard_detects_a_pep604_union() -> None:
    """The detector itself must flag a bare PEP 604 union (regression guard)."""
    tree = ast.parse(
        "_LOCK_FD: int | None = None\n"
        "def f(x: str | None) -> bool | None:\n"
        "    return None\n"
    )
    assert not _has_future_annotations(tree)
    assert _union_hits_in_annotations(tree), "detector failed to catch X | Y unions"


def test_guard_ignores_bitwise_or_outside_annotations() -> None:
    """Bitwise int OR (os.O_CREAT | os.O_RDWR) must NOT be flagged."""
    tree = ast.parse("flags = 1 | 2\nlock_fd = 0\n")
    assert _union_hits_in_annotations(tree) == []
    assert _subscripted_builtin_hits_outside_annotations(tree) == []


def test_guard_detects_subscripted_builtin_alias() -> None:
    """A module-level builtin-generic alias (crashes on 3.9) must be flagged."""
    tree = ast.parse("Registry = dict[str, int]\n")
    assert _subscripted_builtin_hits_outside_annotations(tree), (
        "detector failed to catch dict[str, int] alias outside annotations"
    )


def test_shipped_file_set_is_non_empty() -> None:
    """Guard against a broken glob silently scanning nothing."""
    assert _shipped_files(), "no shipped files discovered — check SHIPPED_PATTERNS"


# ---------------------------------------------------------------------------
# Second trap: possessive quantifiers / atomic groups in regex literals.
#
# ``re`` gained possessive quantifiers (``a*+``, ``a++``, ``a?+``, ``a{m,n}+``)
# and atomic groups (``(?>...)``) in Python 3.11. The bundled universal2
# ``/usr/bin/python3`` is CPython 3.9.6, whose ``re`` raises
# ``re.error: multiple repeat`` on that syntax *at import*, killing the app at
# launch (exactly the spam_filter.py html_to_text hardening constants did this).
# We AST-scan every ``re.<fn>(<str literal>, ...)`` call in shipped files and
# fail on any pattern that uses this 3.11+ syntax.
# ---------------------------------------------------------------------------

# re functions whose FIRST positional arg is the pattern string. (``.sub`` etc.
# on a *compiled* pattern take the replacement first, so we only match calls on
# the ``re`` module itself — see _re_module_aliases.)
_RE_PATTERN_FUNCS = {
    "compile", "search", "match", "fullmatch",
    "sub", "subn", "split", "findall", "finditer",
}


def _re_module_aliases(tree: ast.Module) -> set[str]:
    """Names the ``re`` stdlib module is bound to in this file (handles
    ``import re`` and ``import re as _re``)."""
    aliases = {"re"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "re" and alias.asname:
                    aliases.add(alias.asname)
    return aliases


def _possessive_or_atomic_spans(pattern: str) -> list[tuple[str, int]]:
    """(kind, index) for every possessive quantifier / atomic group in a regex
    source string. Honors backslash escapes and ``[...]`` classes so that
    escaped literals like ``\\++`` (one-or-more literal '+') and class contents
    like ``[*+?]`` are NOT flagged — only true 3.11+ syntax is."""
    hits: list[tuple[str, int]] = []
    i, n = 0, len(pattern)
    in_class = False
    brace_stack: list[int] = []
    while i < n:
        c = pattern[i]
        if c == "\\":            # escaped char -> skip the pair
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c == "(" and pattern[i:i + 3] == "(?>":
            hits.append(("atomic-group", i))
            i += 3
            continue
        if c in "*+?":           # base quantifier; possessive iff followed by '+'
            if i + 1 < n and pattern[i + 1] == "+":
                hits.append(("possessive", i))
                i += 2
                continue
            i += 1
            continue
        if c == "{":
            brace_stack.append(i)
            i += 1
            continue
        if c == "}":
            if brace_stack:
                start = brace_stack.pop()
                inner = pattern[start + 1:i]
                # Only a real {m,n} quantifier (digits/comma) can be possessive.
                if inner and all(ch.isdigit() or ch == "," for ch in inner):
                    if i + 1 < n and pattern[i + 1] == "+":
                        hits.append(("possessive-brace", i))
                        i += 2
                        continue
            i += 1
            continue
        i += 1
    return hits


def _regex_syntax_hits(tree: ast.Module) -> list[tuple[int, str, list[tuple[str, int]]]]:
    """(lineno, pattern, spans) for shipped ``re.<fn>`` calls whose literal
    pattern uses possessive/atomic syntax."""
    aliases = _re_module_aliases(tree)
    out: list[tuple[int, str, list[tuple[str, int]]]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        func = node.func
        if func.attr not in _RE_PATTERN_FUNCS:
            continue
        if not (isinstance(func.value, ast.Name) and func.value.id in aliases):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            spans = _possessive_or_atomic_spans(first.value)
            if spans:
                out.append((first.lineno, first.value, spans))
    return out


@pytest.mark.parametrize("path", _shipped_files(), ids=lambda p: os.path.relpath(p, REPO_ROOT))
def test_shipped_file_has_no_py311_regex_syntax(path: str) -> None:
    """No shipped regex literal may use possessive quantifiers or atomic groups
    (Python 3.11+), which the bundled 3.9 ``re`` rejects at import."""
    tree = _parse(path)
    hits = _regex_syntax_hits(tree)
    rel = os.path.relpath(path, REPO_ROOT)
    assert not hits, (
        f"{rel} uses Python 3.11+ regex syntax (possessive quantifiers or "
        f"atomic groups) that the bundled /usr/bin/python3 (CPython 3.9) "
        f"rejects at import with 're.error: multiple repeat' — a launch crash. "
        f"Fix: use plain greedy quantifiers (\\s*+ -> \\s*); if backtracking is "
        f"a real concern, use a manual linear scanner instead. Offenders: "
        + "; ".join(f"line {ln}: {pat!r} {spans}" for ln, pat, spans in hits)
    )


def test_regex_guard_flags_possessive_and_atomic() -> None:
    """The detector must catch each 3.11+ regex form (regression guard)."""
    assert _possessive_or_atomic_spans(r"<\s*+br>")           # possessive *
    assert _possessive_or_atomic_spans(r"a++b")               # possessive +
    assert _possessive_or_atomic_spans(r"x?+")                # possessive ?
    assert _possessive_or_atomic_spans(r"\d{2,3}+")           # possessive {m,n}
    assert _possessive_or_atomic_spans(r"(?>ab)c")            # atomic group


def test_regex_guard_ignores_39_safe_forms() -> None:
    """Escaped literals, classes, and lazy/greedy quantifiers must NOT flag."""
    for safe in (r"<\s*br>", r"\++", r"\*+", r"\?+", r"[*+?]",
                 r"a*?b", r"a+?b", r"a??b", r"x{2,3}", r"(?:ab)+", r"foo\}+"):
        assert _possessive_or_atomic_spans(safe) == [], safe

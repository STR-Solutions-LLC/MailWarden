#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Regression test for the payload packaging allowlist in app/setup_app.py.

Asserts:
  1. Payload-tree DATA_FILES equals exactly the 9 allowlisted paths and
     contains NO memory/, logs/, .lock, or .claude-mpm entries.
  2. Defaults-tree DATA_FILES still includes the seed JSONs
     (signals.json, blacklist.json, whitelist.json).

Run with:
  cd <repo-root>
  python -m pytest tests/test_payload_allowlist.py -v
"""
from pathlib import Path
import sys

# Locate the repo root and add app/ to sys.path so we can import from setup_app.py
REPO_ROOT = Path(__file__).parent.parent.resolve()
APP_DIR = REPO_ROOT / "app"
sys.path.insert(0, str(APP_DIR))

# Import only the two pure functions from setup_app. We do this by importing
# the module's source, stripping the side-effectful top-level statements
# (shutil.copytree calls, DATA_FILES = ...), and exec'ing just the function defs.
import ast, types, textwrap

_setup_src = (APP_DIR / "setup_app.py").read_text()

# Extract only the function defs and the constants _PAYLOAD_DIRS/_PAYLOAD_FILES
_ns: dict = {"Path": Path, "__builtins__": __builtins__}
_tree = ast.parse(_setup_src)
_wanted_names = {"_tree_to_data_files", "_payload_data_files", "_PAYLOAD_DIRS", "_PAYLOAD_FILES"}
_kept_nodes = [
    n for n in _tree.body
    if (
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in _wanted_names
    ) or (
        isinstance(n, ast.Assign) and any(
            (isinstance(t, ast.Name) and t.id in _wanted_names) for t in n.targets
        )
    )
]
_mod = ast.Module(body=_kept_nodes, type_ignores=[])
exec(compile(_mod, "<setup_app_extracted>", "exec"), _ns)

_tree_to_data_files = _ns["_tree_to_data_files"]
_payload_data_files = _ns["_payload_data_files"]

PAYLOAD_ROOT = REPO_ROOT / "payload" / "MailWarden"
DEFAULTS_ROOT = REPO_ROOT / "resources" / "defaults"


# ---------------------------------------------------------------------------
# Payload allowlist assertions
# ---------------------------------------------------------------------------

def test_payload_data_files_exact_ten():
    """Payload DATA_FILES must contain exactly 10 files (9 originals + the
    engine keychain_store.py copy added by the Keychain migration)."""
    result = _payload_data_files(PAYLOAD_ROOT, "payload/MailWarden")
    all_files = [f for _, files in result for f in files]
    assert len(all_files) == 10, (
        f"Expected 10 payload files, got {len(all_files)}:\n" +
        "\n".join(f"  {f}" for f in sorted(all_files))
    )


def test_payload_data_files_no_junk():
    """Payload DATA_FILES must not contain memory/, logs/, .lock, or .claude-mpm entries."""
    result = _payload_data_files(PAYLOAD_ROOT, "payload/MailWarden")
    all_files = [f for _, files in result for f in files]
    junk_patterns = ["memory", "logs", ".lock", ".claude-mpm"]
    for f in all_files:
        for pat in junk_patterns:
            assert pat not in f, f"Junk pattern '{pat}' found in payload DATA_FILES: {f}"


def test_payload_data_files_allowlisted_paths():
    """Payload DATA_FILES must contain exactly the allowlisted relative paths."""
    result = _payload_data_files(PAYLOAD_ROOT, "payload/MailWarden")
    all_rel = sorted(
        Path(f).relative_to(PAYLOAD_ROOT).as_posix()
        for _, files in result for f in files
    )
    expected = sorted([
        "EULA.md",
        "LICENSE",
        "requirements.txt",
        "blacklist/skip_names.txt",
        "src/daily_report.py",
        "src/file_lock.py",
        "src/keychain_store.py",
        "src/learn_signals.py",
        "src/spam_filter.py",
        "src/utils.py",
    ])
    assert all_rel == expected, (
        f"Payload allowlist mismatch.\nExpected: {expected}\nGot:      {all_rel}"
    )


# ---------------------------------------------------------------------------
# Defaults tree — seed JSONs must still ship
# ---------------------------------------------------------------------------

def test_data_files_payload_wired_to_allowlist_function():
    """Wiring guard: DATA_FILES payload entry must call _payload_data_files, not _tree_to_data_files.

    If line ~91 of setup_app.py is reverted, junk dev artifacts would silently
    ship and every other test in this file would still pass.
    """
    assert '_payload_data_files(LOCAL_PAYLOAD, "payload/MailWarden")' in _setup_src, (
        "DATA_FILES payload wiring must use _payload_data_files (allowlist). "
        "Check line ~91 of app/setup_app.py."
    )
    assert '_tree_to_data_files(LOCAL_PAYLOAD, "payload/MailWarden")' not in _setup_src, (
        "DATA_FILES payload wiring must NOT use _tree_to_data_files — revert detected. "
        "Check line ~91 of app/setup_app.py."
    )


def test_defaults_data_files_includes_seed_jsons():
    """Defaults tree DATA_FILES must include signals.json, blacklist.json, whitelist.json."""
    result = _tree_to_data_files(DEFAULTS_ROOT, "defaults")
    all_files_lower = [Path(f).name.lower() for _, files in result for f in files]
    for required in ("signals.json", "blacklist.json", "whitelist.json"):
        assert required in all_files_lower, (
            f"Defaults tree missing required seed file: {required}\n"
            f"Found: {sorted(all_files_lower)}"
        )

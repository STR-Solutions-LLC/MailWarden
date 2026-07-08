"""Batch 4 (Keychain design plan §9) — build-system + diagnose gate tests.

All headless: the DR-expectation parser and the gate's main() are exercised
with codesign output supplied as text (no bundle, no signing), and the build
wiring is checked by static dependency-presence assertions. Nothing here needs
the macOS Security framework, a Developer ID cert, or a built app.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DR_SCRIPT = REPO_ROOT / "scripts" / "check_designated_requirements.py"


def _load_dr_module():
    spec = importlib.util.spec_from_file_location(
        "check_designated_requirements", DR_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dr = _load_dr_module()


# --- realistic codesign -d -r- fixtures -------------------------------------
# A Developer-ID DR for the outer app (from design plan §4.2 / real codesign).
VALID_APP_DR = (
    'Executable=/Applications/MailWarden.app/Contents/MacOS/MailWarden\n'
    '# designated => identifier "com.strsolutions.mailwarden" '
    'and anchor apple generic '
    'and certificate 1[field.1.2.840.113635.100.6.2.6] '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] '
    'and certificate leaf[subject.OU] = "6BXSAHWH29"\n'
)
# Real DevID python DR (captured from the staged signed bundle): the identifier
# is the bare word `python` — UNQUOTED — because codesign renders simple
# identifiers without quotes. This is what the parser must accept.
VALID_PY_DR = (
    'Executable=/Applications/MailWarden.app/Contents/MacOS/python\n'
    'designated => identifier python and anchor apple generic '
    'and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ '
    'and certificate leaf[subject.OU] = "6BXSAHWH29"\n'
)
# The ad-hoc DR a dev build actually produces (captured from the local bundle):
ADHOC_DR = (
    'Executable=/x/MailWarden.app/Contents/MacOS/python\n'
    '# designated => cdhash H"e9d617985ad64750806f293bae447bd3bd138f4d" '
    'or cdhash H"ad7a9afebd0471090944eae596f378251c807786"\n'
)


# --- evaluate_requirement ----------------------------------------------------
def test_valid_devid_app_dr_passes():
    assert dr.evaluate_requirement(VALID_APP_DR, "com.strsolutions.mailwarden") == []


def test_valid_devid_python_dr_passes():
    assert dr.evaluate_requirement(VALID_PY_DR, "python") == []


def test_wrong_identifier_fails():
    problems = dr.evaluate_requirement(VALID_PY_DR, "org.python.WRONG")
    assert problems
    assert any("identifier" in p for p in problems)


def test_unquoted_identifier_requires_a_boundary():
    # The bare-identifier match must not let a prefix satisfy a longer expected
    # id: a DR that pins `python` must NOT be accepted as `python3`.
    problems = dr.evaluate_requirement(VALID_PY_DR, "python3")
    assert any("identifier" in p for p in problems)


def test_missing_team_ou_fails():
    # Same app identifier but a different team's OU: must fail on the team clause.
    other_team = VALID_APP_DR.replace("6BXSAHWH29", "ZZZZZZZZZZ")
    problems = dr.evaluate_requirement(other_team, "com.strsolutions.mailwarden")
    assert problems == ['missing team OU "6BXSAHWH29"']


def test_adhoc_cdhash_dr_fails_on_both_clauses():
    problems = dr.evaluate_requirement(ADHOC_DR, "python")
    assert len(problems) == 2  # missing identifier AND missing team OU


def test_empty_dr_fails():
    problems = dr.evaluate_requirement("", "com.strsolutions.mailwarden")
    assert len(problems) == 2


# --- check_targets -----------------------------------------------------------
def test_check_targets_all_pass():
    results = dr.check_targets(
        {"app": VALID_APP_DR, "python": VALID_PY_DR},
        {"app": "com.strsolutions.mailwarden", "python": "python"})
    assert results == {"app": [], "python": []}


def test_check_targets_one_target_fails():
    results = dr.check_targets(
        {"app": VALID_APP_DR, "python": ADHOC_DR},
        {"app": "com.strsolutions.mailwarden", "python": "python"})
    assert results["app"] == []
    assert results["python"]  # python leg failed


def test_check_targets_missing_output_is_failure():
    results = dr.check_targets(
        {"app": VALID_APP_DR},  # python DR entirely absent
        {"app": "com.strsolutions.mailwarden", "python": "python"})
    assert results["python"]  # a missing/unsigned binary must not pass silently


# --- frozen-identifier invariant --------------------------------------------
def test_frozen_identifiers_are_the_shipping_invariant():
    # This is the identifier-freeze gate expressed as a test: if someone renames
    # either identifier (which strands every existing keychain item) this fails
    # and forces the reviewed migration procedure in §4.2.
    assert dr.FROZEN == {
        "app": "com.strsolutions.mailwarden",
        "python": "python",
    }
    assert dr.TEAM_OU == "6BXSAHWH29"


# --- main() end-to-end gating (codesign monkeypatched) ----------------------
def test_main_passes_on_matching_drs(monkeypatch, capsys):
    def fake_read(path):
        return VALID_PY_DR if path.endswith("/python") else VALID_APP_DR
    monkeypatch.setattr(dr, "read_designated_requirement", fake_read)
    rc = dr.main(["/Applications/MailWarden.app"])
    assert rc == 0
    assert "PASSED" in capsys.readouterr().out


def test_main_fails_when_fed_a_wrong_expectation(monkeypatch, capsys):
    # Real (correct) DRs, but the caller asserts the WRONG python identifier.
    # Proves the gate actually gates rather than rubber-stamping.
    def fake_read(path):
        return VALID_PY_DR if path.endswith("/python") else VALID_APP_DR
    monkeypatch.setattr(dr, "read_designated_requirement", fake_read)
    rc = dr.main([
        "/Applications/MailWarden.app",
        "--expect-python-identifier", "org.python.WRONG",
    ])
    assert rc == 1
    assert "FAILED" in capsys.readouterr().out


def test_main_fails_on_adhoc_build(monkeypatch, capsys):
    monkeypatch.setattr(dr, "read_designated_requirement", lambda p: ADHOC_DR)
    rc = dr.main(["/Applications/MailWarden.app"])
    assert rc == 1


# --- dependency-presence: build wiring --------------------------------------
def test_build_installer_installs_pyobjc_security():
    text = (REPO_ROOT / "build_installer.sh").read_text()
    assert "pyobjc-framework-Security>=${PYOBJC_CORE_MAJOR}.0" in text


def test_build_installer_invokes_dr_gate():
    text = (REPO_ROOT / "build_installer.sh").read_text()
    assert "check_designated_requirements.py" in text
    # It must be a hard gate (die on failure), not advisory.
    assert "Designated-requirement gate FAILED" in text


def test_setup_app_packages_include_security():
    text = (REPO_ROOT / "app" / "setup_app.py").read_text()
    # In the py2app packages= list, next to ServiceManagement.
    assert '"Security",' in text


def test_diagnose_gate_covers_security():
    text = (REPO_ROOT / "app" / "mailwarden_app" / "app_entrypoint.py").read_text()
    # Module in the import loop AND the authoritative from-import symbol check.
    assert '"Security",' in text
    assert "from Security import SecItemCopyMatching" in text

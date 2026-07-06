#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Feature 3 tests — unify the account ``enabled``-key default to ON.

A MISSING ``enabled`` key on an account now means ON / filtered EVERYWHERE, while
an EXPLICIT ``enabled: false`` still disables the account. These tests lock in
that invariant across the correctness-critical gates (the ones that actually move
mail) and add a lighter drift-guard over the GUI display sites.

Three account shapes are exercised throughout:
  * absent ``enabled`` key           -> ON  (processed / reported / shown enabled)
  * explicit ``enabled: False``      -> OFF (skipped / excluded / shown disabled)
  * explicit ``enabled: True``       -> ON

Seams:
  * spam_filter._owner_identities and daily_report.build_report_body are isolable
    pure functions -> tested BEHAVIORALLY with real calls.
  * The run_filter enable gate (~6492) and the daily_report send gate (~1549) are
    inline predicates inside heavy IMAP/IO functions with no extractable helper;
    driving them fully would be the very "full IMAP run" we must avoid. They are
    covered by a source drift-guard (the gate must read ``.get("enabled", True)``,
    never ``, False``) plus a truth-table documenting the resulting behavior.
  * GUI display sites (dashboard/menu_bar/app_entrypoint) get a lighter file-level
    drift-guard so a future edit that drops the default is caught.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_enabled_default.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/ memory
directory is never read or written (LEARNER_STATE_PATH is monkeypatched to tmp).
"""
import inspect
import logging
import os
import sys
from datetime import datetime

import pytest  # noqa: F401  (parity with the suite / fixtures)

# Dual sys.path: the engine tree (flat modules) and the app/ root (the
# mailwarden_app package) both go on the path (matches tests/test_fp_dashboard_approve.py).
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402,F401  (REAL flock — never mocked)
import spam_filter  # noqa: E402
import daily_report  # noqa: E402

_LOG = logging.getLogger("test_enabled_default")
_LOG.addHandler(logging.NullHandler())

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ===========================================================================
# Gate #2 (behavioral) — spam_filter._owner_identities (~2695)
# An absent-key account's owner identity IS trusted; an explicit-False account's
# is NOT. (This gate decides whose Whitelist/Blacklist/APPROVE commands are
# honored, so a wrong default is a real security/behavior bug.)
# ===========================================================================

def _three_shape_owner_config() -> dict:
    """One config carrying all three account shapes; smtp empty so the only
    identities come from the accounts themselves."""
    return {
        "accounts": [
            {"username": "absent@x.com"},                      # absent -> ON
            {"username": "off@x.com", "enabled": False},       # explicit OFF
            {"username": "on@x.com", "enabled": True},         # explicit ON
        ],
        "smtp": {},
    }


def test_owner_identities_absent_enabled_key_is_included():
    ids = spam_filter._owner_identities(_three_shape_owner_config())
    assert "absent@x.com" in ids, \
        "an account with NO enabled key must be treated as ON (owner identity trusted)"


def test_owner_identities_explicit_false_is_excluded():
    ids = spam_filter._owner_identities(_three_shape_owner_config())
    assert "off@x.com" not in ids, \
        "an explicit enabled:false account must stay disabled (identity NOT trusted)"


def test_owner_identities_explicit_true_is_included():
    ids = spam_filter._owner_identities(_three_shape_owner_config())
    assert "on@x.com" in ids


# ===========================================================================
# Gate #3a (behavioral) — daily_report.build_report_body monitored list (~1228)
# The "Accounts monitored: N (names)" line must count an absent-key account and
# omit an explicit-False one.
# ===========================================================================

_MIN_DECISIONS = {
    "per_account": {},           # len 0 -> single-account (else) branch
    "evaluated": 0,
    "spam_moved": 0,
    "not_spam": 0,
    "errors": 0,
    "spam_entries": [],
}


def _report_body_for(account: dict, monkeypatch, tmp_path) -> str:
    """Render build_report_body for a single-account config, hermetically
    (LEARNER_STATE_PATH pointed at a nonexistent tmp file)."""
    monkeypatch.setattr(daily_report, "LEARNER_STATE_PATH", tmp_path / "no_learner_state.json")
    config = {
        "accounts": [account],
        "filter": {"dry_run": True},
        "signal_learner": {},
    }
    return daily_report.build_report_body(
        config, dict(_MIN_DECISIONS), datetime.now(), 0,
        {"derived_from_examples": 0})


def test_report_monitored_list_absent_key_account_is_counted(monkeypatch, tmp_path):
    body = _report_body_for({"name": "Absent Acct"}, monkeypatch, tmp_path)
    assert "Accounts monitored: 1 (Absent Acct)" in body, \
        "an account with NO enabled key must appear in the report's monitored list"


def test_report_monitored_list_explicit_false_is_excluded(monkeypatch, tmp_path):
    body = _report_body_for(
        {"name": "Off Acct", "enabled": False}, monkeypatch, tmp_path)
    assert "Accounts monitored: 0 ()" in body
    assert "Off Acct" not in body, \
        "an explicit enabled:false account must be excluded from the monitored list"


def test_report_monitored_list_explicit_true_is_counted(monkeypatch, tmp_path):
    body = _report_body_for(
        {"name": "On Acct", "enabled": True}, monkeypatch, tmp_path)
    assert "Accounts monitored: 1 (On Acct)" in body


# ===========================================================================
# Gate #1 — spam_filter.run_filter enable gate (~6492), and
# Gate #3b — daily_report.main send gate (~1549).
# No isolable helper exists; the smallest honest seam is the gate expression
# itself. Source drift-guard: the real gate line must default absent -> ON
# (``.get("enabled", True)``) and must NOT reintroduce the absent -> OFF default.
# ===========================================================================

def test_run_filter_enable_gate_defaults_absent_to_on():
    src = inspect.getsource(spam_filter.run_filter)
    assert 'account.get("enabled", True)' in src, \
        "run_filter's per-account gate must default a missing enabled key to ON"
    assert 'enabled", False' not in src, \
        "run_filter must not reintroduce the absent->OFF default anywhere"


def test_report_send_gate_defaults_absent_to_on():
    src = inspect.getsource(daily_report.main)
    assert 'a.get("enabled", True)' in src, \
        "the daily-report send gate must default a missing enabled key to ON"
    assert 'enabled", False' not in src, \
        "the send gate must not reintroduce the absent->OFF default"


def test_enabled_default_truth_table_absent_on_false_off():
    """Documents the exact ``.get("enabled", True)`` semantics every flipped gate
    now relies on: absent -> ON, explicit False -> OFF, explicit True -> ON."""
    assert {}.get("enabled", True) is True                     # absent  -> ON
    assert {"enabled": False}.get("enabled", True) is False    # explicit -> OFF
    assert {"enabled": True}.get("enabled", True) is True      # explicit -> ON


# ===========================================================================
# GUI display sites (lighter touch) — dashboard badges/labels, menu_bar pause
# state, app_entrypoint CLI status. A file-level drift-guard: each must carry
# the absent->ON default and none may reintroduce the absent->OFF default.
# ===========================================================================

@pytest.mark.parametrize("relpath, must_contain", [
    ("app/mailwarden_app/dashboard.py", '"Yes" if a.get("enabled", True) else "No"'),
    ("app/mailwarden_app/menu_bar.py", 'a.get("enabled", True) for a in accounts'),
    ("app/mailwarden_app/app_entrypoint.py", "a.get('enabled', True)"),
])
def test_gui_display_sites_default_absent_to_on(relpath, must_contain):
    with open(os.path.join(_REPO_ROOT, relpath), encoding="utf-8") as f:
        text = f.read()
    assert must_contain in text, \
        f"{relpath} must default a missing enabled key to ON at its display site"
    assert 'enabled", False' not in text, \
        f'{relpath} must not reintroduce .get("enabled", False)'
    assert "enabled', False" not in text, \
        f"{relpath} must not reintroduce .get('enabled', False)"

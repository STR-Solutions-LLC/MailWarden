#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Design-intent audit fixes (Batch D):

Finding 1 — Lists tab crash on dict-shaped blacklist entries.
  The blacklist store may hold provenance objects
  {"value","scope"[,"provenance"]} written by APPROVE "block sender" replies
  and by authored Unwanted-Categories rules. The Lists tab used to call
  .lower() on the bare entry, which crashed on a dict (AttributeError, silently
  swallowed by Tk). dashboard._entry_value now extracts the value from either
  shape, and every read/compare/import path routes through it WITHOUT flattening
  the stored dict on any write path.

Finding 2 — Daily-report time setting removed (product decision: no-op → gone).
  The report runs statically at 08:00 via the SMAppService plist; nothing read
  summary.hour/minute. The Settings tab control, the setup wizard's Time entry,
  the false confirmation dialog, and the config defaults are all removed.
  Existing configs carrying summary.hour/minute must still load (silently
  ignored, never crash).

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_batchD_lists_report_time.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
directory is never read or written (paths.*_PATH are monkeypatched to tmp).
"""
import inspect
import json
import os
import sys

import pytest

# Dual sys.path: engine tree (flat modules) + app/ root (mailwarden_app package).
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402,F401  (REAL flock — never mocked)
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402


def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _read_json(path):
    with open(path, "r") as f:
        return json.load(f)


@pytest.fixture
def tmp_memory(tmp_path, monkeypatch):
    """Redirect the app data-file paths these tests touch into tmp_path."""
    mem = tmp_path / "memory"
    cfg = tmp_path / "config"
    mem.mkdir()
    cfg.mkdir()
    monkeypatch.setattr(app_paths, "MEMORY_DIR", mem)
    monkeypatch.setattr(app_paths, "CONFIG_DIR", cfg)
    monkeypatch.setattr(app_paths, "CONFIG_PATH", cfg / "config.json")
    monkeypatch.setattr(app_paths, "WHITELIST_PATH", mem / "whitelist.json")
    monkeypatch.setattr(app_paths, "BLACKLIST_PATH", mem / "blacklist.json")
    return tmp_path


# ---------------------------------------------------------------------------
# Finding 1 — _entry_value normalizes every entry shape
# ---------------------------------------------------------------------------

def test_entry_value_string():
    assert dashboard._entry_value("spam@bad.com") == "spam@bad.com"


def test_entry_value_dict():
    assert dashboard._entry_value({"value": "x@y.com", "scope": "all"}) == "x@y.com"


def test_entry_value_dict_with_provenance():
    entry = {"value": "z@w.com", "scope": ["acct-1"],
             "provenance": [{"id": "rule-7", "scope": ["acct-1"]}]}
    assert dashboard._entry_value(entry) == "z@w.com"


def test_entry_value_malformed_returns_empty():
    assert dashboard._entry_value({"scope": "all"}) == ""   # dict, no "value"
    assert dashboard._entry_value({"value": 123}) == ""      # non-string value
    assert dashboard._entry_value(None) == ""
    assert dashboard._entry_value(42) == ""


# ---------------------------------------------------------------------------
# Finding 1 — _absorb_row (CSV/XLSX import) dedups against dicts, preserves them
# ---------------------------------------------------------------------------

def _empty_lists():
    wl = {"addresses": [], "domains": []}
    bl = {"addresses": [], "domains": [], "display_names": [],
          "subject_keywords": []}
    return wl, bl


def test_absorb_row_dedups_against_dict_address_and_preserves_it():
    wl, bl = _empty_lists()
    bl["addresses"].append({"value": "spam@bad.com", "scope": "all"})

    added, skipped = dashboard._absorb_row(
        ["list", "address"], ["blacklist", "spam@bad.com"], wl, bl)

    assert (added, skipped) == (0, 1)
    # The dict entry is untouched — never flattened to a bare string.
    assert bl["addresses"] == [{"value": "spam@bad.com", "scope": "all"}]


def test_absorb_row_adds_new_domain_alongside_dict():
    wl, bl = _empty_lists()
    bl["domains"].append({"value": "bad.com", "scope": "all"})

    added, skipped = dashboard._absorb_row(
        ["list", "domain"], ["blacklist", "other.com"], wl, bl)

    assert (added, skipped) == (1, 0)
    assert {"value": "bad.com", "scope": "all"} in bl["domains"]
    assert "other.com" in bl["domains"]


def test_import_tabular_csv_preserves_dict_entry(tmp_memory, tmp_path):
    """End-to-end regression: a provenance dict on disk once crashed the whole
    CSV import at the .lower() dedup. Import must now succeed, dedup against the
    dict, and leave the dict (with provenance) intact on disk."""
    bl = {"version": "1.0",
          "addresses": [{"value": "spam@bad.com", "scope": "all",
                         "provenance": [{"id": "rule-1", "scope": "all"}]}],
          "display_names": [], "domains": [], "subject_keywords": [],
          "last_updated": ""}
    _write_json(app_paths.BLACKLIST_PATH, bl)
    _write_json(app_paths.WHITELIST_PATH,
                {"version": "1.0", "addresses": [], "domains": [],
                 "last_updated": ""})

    csv_path = tmp_path / "import.csv"
    csv_path.write_text(
        "list,address\n"
        "blacklist,spam@bad.com\n"    # duplicate of the dict entry -> skipped
        "blacklist,new@evil.com\n")   # new -> added

    added, skipped = dashboard._import_tabular_csv(csv_path)

    assert added == 1
    assert skipped == 1

    out = _read_json(app_paths.BLACKLIST_PATH)
    # Provenance dict survived the import untouched.
    assert {"value": "spam@bad.com", "scope": "all",
            "provenance": [{"id": "rule-1", "scope": "all"}]} in out["addresses"]
    # The new hand-added entry was appended as a bare string.
    assert "new@evil.com" in out["addresses"]


# ---------------------------------------------------------------------------
# Finding 2 — daily-report time setting removed, legacy keys ignored
# ---------------------------------------------------------------------------

def test_summary_defaults_have_no_hour_minute():
    summary = config_io.DEFAULT_CONFIG["summary"]
    assert "hour" not in summary
    assert "minute" not in summary
    assert "recipient" in summary


def test_legacy_summary_hour_minute_load_without_crash(tmp_memory):
    """A config saved by an older build still carries summary.hour/minute;
    load_config must not crash and the recipient must survive."""
    _write_json(app_paths.CONFIG_PATH, {
        "summary": {"recipient": "me@x.com", "hour": 9, "minute": 30},
        "accounts": [],
    })
    cfg = config_io.load_config()   # must not raise
    assert cfg["summary"]["recipient"] == "me@x.com"


def test_dashboard_report_time_control_removed():
    assert not hasattr(dashboard.SettingsTab, "_on_apply_report_time")
    src = inspect.getsource(dashboard)
    assert "_report_time_var" not in src
    assert "will now run at" not in src


def test_setup_finalize_writes_recipient_without_time():
    from mailwarden_app.setup_assistant import _merge_finalized_config
    cfg = {
        "accounts": [], "anthropic": {}, "filter": {}, "smtp": {},
        "summary": {"recipient": ""}, "eula": {},
        "ui": {"menu_bar_enabled": True},
    }
    result = _merge_finalized_config(
        cfg=cfg, accounts=[], is_fresh_install=True,
        api_key="sk-test", recipient="you@x.com", menu_bar_enabled=True)
    assert result["summary"]["recipient"] == "you@x.com"
    assert "hour" not in result["summary"]
    assert "minute" not in result["summary"]

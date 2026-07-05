#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Feature 2 tests — Dashboard Dropped-rules Restore panel.

Feature 2 restores email-dropped (status=="retired") ai_refinements only:
  * config_io.list_retired_refinements returns ONLY records explicitly marked
    "retired" (an absent status must NOT count — unlike list_active_refinements).
  * config_io.restore_refinement is the config_io twin of the engine's
    spam_filter.unretire_ai_refinement (the trees never import each other, so the
    semantics are duplicated). It flips status retired -> active, drops
    retired_at, stamps last_reinforced, preserves scope + all other fields, is
    retired-only + idempotent, and logs exactly one restored_by_owner event on
    success. A drift-guard feeds one identical record to BOTH and asserts they
    agree.
  * SignalsTab._on_restore_dropped maps success/None to dialogs and NEVER claims
    a restore that didn't happen (#7/#8 honesty rule).
  * pending_retired_message now points at the Dropped-rules panel.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_dropped_rules_restore.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/ memory
directory is never read or written (the path constants are monkeypatched to
tmp, and the IO helpers are stubbed). file_lock is the REAL flock — never mocked.
"""
import copy
import inspect
import logging
import os
import sys

import pytest  # noqa: F401  (parity with the suite / fixtures)

# Dual sys.path: the engine tree (flat modules) and the app/ root (the
# mailwarden_app package) both go on the path (matches tests/test_fp_dashboard_approve.py).
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402,F401  (REAL flock — never mocked)
import spam_filter  # noqa: E402
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402

_LOG = logging.getLogger("test_dropped_rules_restore")
_LOG.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# config_io.list_retired_refinements
# ---------------------------------------------------------------------------

def test_list_retired_returns_only_explicitly_retired(monkeypatch, tmp_path):
    """One active, one absent-status, one retired -> only the retired one.
    An absent status must NOT count as retired (the exact predicate)."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")
    data = {"signals": {}, "ai_refinements": [
        {"id": "R-active", "status": "active"},
        {"id": "R-absent"},                         # no status -> NOT retired
        {"id": "R-retired", "status": "retired"},
    ]}
    monkeypatch.setattr(config_io, "load_signals", lambda: data)

    out = config_io.list_retired_refinements()
    assert [r["id"] for r in out] == ["R-retired"]


# ---------------------------------------------------------------------------
# config_io.restore_refinement
# ---------------------------------------------------------------------------

def _drive_restore(monkeypatch, tmp_path, existing, refinement_id,
                   source="dashboard"):
    """Drive config_io.restore_refinement with IO stubbed and SIGNALS_PATH pointed
    at tmp (so the REAL file_lock writes its lock file under tmp, not the user's
    memory dir).

    Returns (result, state, events, saved) where state["saves"] counts
    save_signals calls and saved["data"] holds the signals dict handed to it.
    load_signals returns the SAME dict restore_refinement mutates in place, so
    the returned record and the persisted record are one object.
    """
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")

    data = {"signals": {}, "ai_refinements": list(existing)}
    state = {"saves": 0}
    events = []
    saved = {}
    monkeypatch.setattr(config_io, "load_signals", lambda: data)

    def _save(d):
        state["saves"] += 1
        saved["data"] = d
    monkeypatch.setattr(config_io, "save_signals", _save)
    monkeypatch.setattr(config_io, "append_refinement_log",
                        lambda ev: events.append(ev))

    result = config_io.restore_refinement(refinement_id, source=source)
    return result, state, events, saved


def test_restore_success_flips_status_and_logs_once(monkeypatch, tmp_path):
    rec = {"id": "R-1", "status": "retired",
           "retired_at": "2026-01-01T00:00:00", "headline": "Drop me",
           "first_learned": "2025-12-01T00:00:00"}
    result, state, events, saved = _drive_restore(
        monkeypatch, tmp_path, [rec], "R-1")

    assert result is not None
    assert result["status"] == "active"
    assert "retired_at" not in result
    assert result.get("last_reinforced")             # stamped to now
    # The persisted record is the same flipped object.
    persisted = saved["data"]["ai_refinements"][0]
    assert persisted["status"] == "active"
    assert "retired_at" not in persisted
    assert state["saves"] == 1
    # Exactly ONE restored_by_owner event, carrying id + source + headline.
    logs = [e for e in events if e.get("event") == "restored_by_owner"]
    assert len(logs) == 1
    assert logs[0]["id"] == "R-1"
    assert logs[0]["source"] == "dashboard"
    assert logs[0]["headline"] == "Drop me"


def test_restore_idempotent_already_active_no_save_no_log(monkeypatch, tmp_path):
    rec = {"id": "R-1", "status": "active", "headline": "h"}
    result, state, events, saved = _drive_restore(
        monkeypatch, tmp_path, [rec], "R-1")

    assert result is None
    assert state["saves"] == 0
    assert events == []


def test_restore_unknown_id_no_save_no_log(monkeypatch, tmp_path):
    rec = {"id": "R-other", "status": "retired", "headline": "h"}
    result, state, events, saved = _drive_restore(
        monkeypatch, tmp_path, [rec], "R-nope")

    assert result is None
    assert state["saves"] == 0
    assert events == []


def test_restore_preserves_scope(monkeypatch, tmp_path):
    rec = {"id": "R-1", "status": "retired", "scope": ["a@x"], "headline": "h"}
    result, state, events, saved = _drive_restore(
        monkeypatch, tmp_path, [rec], "R-1")

    assert result is not None
    assert result["scope"] == ["a@x"]                # untouched by the flip


def test_restore_has_no_dry_run_gate():
    """Restore must work regardless of the filter's dry_run flag — verify the
    twin genuinely never consults it (no gate to slip past)."""
    src = inspect.getsource(config_io.restore_refinement)
    assert "dry_run" not in src


def test_engine_parity_restore_matches_unretire(monkeypatch, tmp_path):
    """Drift-guard: feed one IDENTICAL retired record to the config_io twin AND
    the engine's spam_filter.unretire_ai_refinement, and assert the resulting
    status / absence-of-retired_at agree."""
    base = {"id": "R-P", "status": "retired",
            "retired_at": "2026-01-01T00:00:00",
            "headline": "h", "scope": "all"}
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)

    # config_io side (twin).
    app_data = {"signals": {}, "ai_refinements": [copy.deepcopy(base)]}
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals_app.json")
    monkeypatch.setattr(config_io, "load_signals", lambda: app_data)
    monkeypatch.setattr(config_io, "save_signals", lambda d: None)
    monkeypatch.setattr(config_io, "append_refinement_log", lambda ev: None)
    app_restored = config_io.restore_refinement("R-P", source="dashboard")

    # engine side (source of truth) — pass a NullHandler-backed logger.
    eng_data = {"signals": {}, "ai_refinements": [copy.deepcopy(base)]}
    monkeypatch.setattr(spam_filter, "SIGNALS_PATH", mem / "signals_eng.json")
    monkeypatch.setattr(spam_filter, "load_signals", lambda: eng_data)
    monkeypatch.setattr(spam_filter, "save_signals", lambda d: None)
    monkeypatch.setattr(spam_filter, "append_refinement_log", lambda ev: None)
    eng_restored = spam_filter.unretire_ai_refinement("R-P", _LOG)

    assert app_restored is not None and eng_restored is not None
    assert app_restored["status"] == eng_restored["status"] == "active"
    assert "retired_at" not in app_restored
    assert "retired_at" not in eng_restored


# ---------------------------------------------------------------------------
# Dashboard handler: SignalsTab._on_restore_dropped
# Never claim a restore that didn't happen (#7/#8 honesty rule).
# ---------------------------------------------------------------------------

class _MsgCapture:
    def __init__(self):
        self.calls = []

    def showinfo(self, *a, **k):
        self.calls.append(("showinfo", a, k))

    def showerror(self, *a, **k):
        self.calls.append(("showerror", a, k))

    def showwarning(self, *a, **k):
        self.calls.append(("showwarning", a, k))


class _FakeSelf:
    def __init__(self):
        self.refreshed = False

    def refresh(self):
        self.refreshed = True


def _drive_on_restore(monkeypatch, twin_result, refinement_id="R-9"):
    """Call SignalsTab._on_restore_dropped with a bare fake self and a stubbed
    config_io.restore_refinement returning twin_result. Returns the messagebox
    capture, the fake self, and the args captured by the twin stub."""
    msgs = _MsgCapture()
    monkeypatch.setattr(dashboard, "messagebox", msgs)
    captured = {}

    def _restore(rid, source="dashboard"):
        captured["id"] = rid
        captured["source"] = source
        return twin_result
    monkeypatch.setattr(config_io, "restore_refinement", _restore)

    fake = _FakeSelf()
    dashboard.SignalsTab._on_restore_dropped(fake, refinement_id)
    return msgs, fake, captured


def test_handler_restore_success_info_only_names_id(monkeypatch):
    msgs, fake, cap = _drive_on_restore(
        monkeypatch, {"id": "R-9", "status": "active"})
    kinds = [c[0] for c in msgs.calls]
    assert kinds == ["showinfo"]                     # exactly one info dialog
    assert "showerror" not in kinds
    assert "R-9" in msgs.calls[0][1][1]              # body names the rule id
    assert fake.refreshed is True


def test_handler_restore_none_is_honest_not_a_success_claim(monkeypatch):
    msgs, fake, cap = _drive_on_restore(monkeypatch, None)
    assert len(msgs.calls) == 1
    kind, args, kwargs = msgs.calls[0]
    assert kind == "showinfo"
    assert args[0] == "Nothing to restore"           # NOT a success title
    assert fake.refreshed is True


def test_handler_passes_dashboard_source_to_twin(monkeypatch):
    msgs, fake, cap = _drive_on_restore(
        monkeypatch, {"id": "R-9", "status": "active"})
    assert cap["source"] == "dashboard"
    assert cap["id"] == "R-9"


# ---------------------------------------------------------------------------
# Render / build-sections source-inspection (headless — no Tk instantiation)
# ---------------------------------------------------------------------------

def test_render_dropped_wires_list_and_restore():
    # _render_dropped fetches the retired list; the per-card builder wires the
    # Restore button to the handler (plan structure: card builder owns the button).
    render_src = inspect.getsource(dashboard.SignalsTab._render_dropped)
    assert "list_retired_refinements" in render_src
    card_src = inspect.getsource(dashboard.SignalsTab._render_dropped_card)
    assert "_on_restore_dropped" in card_src


def test_build_sections_adds_dropped_box():
    src = inspect.getsource(dashboard.SignalsTab._build_sections)
    assert "_dropped_box" in src


# ---------------------------------------------------------------------------
# pending_retired_message — now points at the Dropped-rules panel
# ---------------------------------------------------------------------------

def test_pending_retired_message_points_at_dropped_rules_panel():
    msg = dashboard.pending_retired_message()
    assert msg                                       # still non-empty
    assert "Dropped rules" in msg
    assert "can't restore a dropped rule" not in msg  # stale claim is gone

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Feature 1 + finding #9 tests.

Feature 1 — Dashboard "Approve" for false_positive pending proposals:
  * config_io.apply_fp_narrowing_from_pending twin mirrors the engine's
    email-YES false_positive arm (verify-before-ack + self-heal, then the same
    applied / already_active / retired state logic) so a Dashboard approval
    lands in the identical state an email YES would.
  * The parser it duplicates from spam_filter.py must stay byte-identical
    (drift-guard).
  * SignalsTab._on_approve_pending maps the five outcomes to dialogs and NEVER
    shows a success (showinfo) on a no-op / failure (#7/#8 honesty rule).

Finding #9 — kind-aware daily-report copy:
  * _pending_was_emailed classifies the four proposal kinds.
  * build_pending_signals_section leads with the now-universal Dashboard path,
    only offers the email reply for emailed kinds, and no longer emits the
    FP-only "Fwd: False Positive" re-teach line for non-FP kinds.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_fp_dashboard_approve.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/ memory
directory is never read or written (the path constants are monkeypatched to
tmp, and the IO helpers are stubbed). file_lock is the REAL flock — never mocked.
"""
import inspect
import logging
import os
import sys

import pytest  # noqa: F401  (parity with the suite / fixtures)

# Dual sys.path: the engine tree (flat modules) and the app/ root (the
# mailwarden_app package) both go on the path (matches tests/test_batch6.py).
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402,F401  (REAL flock — never mocked)
import spam_filter  # noqa: E402
import daily_report  # noqa: E402
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402

_LOG = logging.getLogger("test_fp_dashboard_approve")
_LOG.addHandler(logging.NullHandler())


# A realistic false-positive analysis in the exact five-label plain form the
# FP prompt requests. The parser captures PROPOSED CHANGE (bounded by TRADEOFF)
# and TRADEOFF (bounded by MY RECOMMENDATION).
FP_ANALYSIS = """WHY IT WAS FLAGGED:
The message used urgency language and a discount code.

WHY THE USER IS RIGHT:
This is the owner's real bank, whose domain is already whitelisted.

PROPOSED CHANGE:
Do not flag DKIM-signed transactional mail from bankofamerica.com as spam.

TRADEOFF:
Low risk — the narrowing is scoped to a single verified domain.

MY RECOMMENDATION:
Apply this change.
"""

# The same analysis with Markdown-dressed labels (## heading / **bold**), which
# real models routinely emit and the tolerant parser must normalize.
FP_ANALYSIS_DRESSED = """## WHY IT WAS FLAGGED
The message used urgency language.

**PROPOSED CHANGE:**
Do not flag DKIM-signed transactional mail from bankofamerica.com as spam.

**TRADEOFF:**
Low risk.

## MY RECOMMENDATION
Apply this change.
"""


# ---------------------------------------------------------------------------
# Twin: config_io.apply_fp_narrowing_from_pending
# ---------------------------------------------------------------------------

def _drive_fp_apply(monkeypatch, tmp_path, conv, *, call_sfid=None,
                    existing=None, fixed_id=None):
    """Drive config_io.apply_fp_narrowing_from_pending with IO stubbed and the
    two sidecar paths pointed at tmp (so the REAL file_lock writes its lock
    files under tmp, not the user's memory dir).

    Returns (result, conv, state, events, saved) where state tracks whether
    save_signals / save_pending_signals were called and saved["data"] holds the
    signals dict handed to save_signals.
    """
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_paths, "PENDING_SIGNALS_PATH",
                        mem / "pending_signals.json")
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")

    state = {"saved_signals": False, "saved_pending": False}
    events = []
    saved = {}
    monkeypatch.setattr(config_io, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": [conv]})
    monkeypatch.setattr(config_io, "save_pending_signals",
                        lambda data: state.__setitem__("saved_pending", True))
    monkeypatch.setattr(config_io, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": list(existing or [])})

    def _save_signals(data):
        state["saved_signals"] = True
        saved["data"] = data
    monkeypatch.setattr(config_io, "save_signals", _save_signals)
    monkeypatch.setattr(config_io, "append_refinement_log",
                        lambda ev: events.append(ev))
    if fixed_id is not None:
        monkeypatch.setattr(config_io, "_mint_refinement_id",
                            lambda signals: fixed_id)

    result = config_io.apply_fp_narrowing_from_pending(
        call_sfid or conv["id"], source="dashboard")
    return result, conv, state, events, saved


def _fp_conv(**over):
    conv = {
        "id": "SFID-20260704-fp01",
        "status": "awaiting_reply",
        "original_subject": "Your statement is ready",
        # no "kind" -> defaults to false_positive
        "proposed_changes": {
            "signals_to_narrow": {"from_analysis": "Do not flag bank mail."},
            "tradeoffs": "Low risk.",
        },
        "conversation_history": [],
    }
    conv.update(over)
    return conv


def test_twin_applied_persists_legitimate_refinement_and_resolves_conv(
        monkeypatch, tmp_path):
    conv = _fp_conv()
    result, conv, state, events, saved = _drive_fp_apply(
        monkeypatch, tmp_path, conv)

    assert result["status"] == "applied"
    assert result["id"].startswith("R-")
    # Exactly one "applied" event, carrying the SFID and dashboard source.
    applied = [e for e in events if e.get("event") == "applied"]
    assert len(applied) == 1
    assert applied[0]["sfid"] == "SFID-20260704-fp01"
    assert applied[0]["id"] == result["id"]
    assert applied[0]["source"] == "dashboard"
    # The persisted refinement is a LEGITIMATE, scope-all fp_narrowing.
    record = saved["data"]["ai_refinements"][-1]
    assert record["kind"] == "fp_narrowing"
    assert record["verdict"] == "legitimate"
    assert record["scope"] == "all"
    assert record["status"] == "active"
    assert record["headline"] == "Do not flag bank mail."
    # The conversation was resolved (approved) and persisted.
    assert conv["status"] == "approved"
    assert conv["resolution"] == "approved"
    assert state["saved_signals"] is True
    assert state["saved_pending"] is True


def test_twin_self_heal_reparses_api_analysis(monkeypatch, tmp_path):
    """Empty proposed_changes but a parseable api_analysis -> applied, and the
    healed changes are written back onto the conversation."""
    conv = _fp_conv(proposed_changes={}, api_analysis=FP_ANALYSIS)
    result, conv, state, events, saved = _drive_fp_apply(
        monkeypatch, tmp_path, conv)

    assert result["status"] == "applied"
    # The conversation's proposed_changes was healed from the analysis.
    assert conv["proposed_changes"]["signals_to_narrow"]["from_analysis"] == (
        "Do not flag DKIM-signed transactional mail from bankofamerica.com as spam.")
    record = saved["data"]["ai_refinements"][-1]
    assert record["headline"] == (
        "Do not flag DKIM-signed transactional mail from bankofamerica.com as spam.")
    assert [e["event"] for e in events] == ["applied"]


def test_twin_no_change_when_nothing_appliable(monkeypatch, tmp_path):
    """Both proposed_changes and api_analysis empty -> no signals write, conv
    stays awaiting_reply, one apply_failed event."""
    conv = _fp_conv(proposed_changes={}, api_analysis="")
    result, conv, state, events, saved = _drive_fp_apply(
        monkeypatch, tmp_path, conv)

    assert result == {"status": "no_change"}
    assert state["saved_signals"] is False
    assert conv["status"] == "awaiting_reply"      # left pending, untouched
    failed = [e for e in events if e.get("event") == "apply_failed"]
    assert len(failed) == 1
    assert failed[0]["sfid"] == "SFID-20260704-fp01"
    assert "applied" not in [e["event"] for e in events]


# The deterministic id the twin derives from _fp_conv()'s SFID (finding 3):
# 'SFID-20260704-fp01' -> 'R-20260704-fp01'.
_DETERMINISTIC_RID = "R-20260704-fp01"


def test_twin_already_active_no_double_log(monkeypatch, tmp_path):
    """When the DETERMINISTIC id already names an ACTIVE rule the apply is a
    no-op: no signals write, no log, but the conv is still resolved. (This is
    exactly the cross-channel case — a second Approve/YES for a proposal whose
    rule the first channel already wrote.)"""
    conv = _fp_conv()
    result, conv, state, events, saved = _drive_fp_apply(
        monkeypatch, tmp_path, conv,
        existing=[{"id": _DETERMINISTIC_RID, "status": "active", "headline": "h"}])

    assert result["status"] == "already_active"
    assert result["id"] == _DETERMINISTIC_RID
    assert state["saved_signals"] is False
    assert events == []                            # re-approval never double-logs
    assert conv["status"] == "approved"


def test_twin_retired_leaves_conv_pending_and_logs_apply_failed(
        monkeypatch, tmp_path):
    """When the DETERMINISTIC id names a RETIRED rule it cannot be reactivated:
    no write, conv stays pending, one apply_failed event."""
    conv = _fp_conv()
    result, conv, state, events, saved = _drive_fp_apply(
        monkeypatch, tmp_path, conv,
        existing=[{"id": _DETERMINISTIC_RID, "status": "retired", "headline": "h"}])

    assert result["status"] == "retired"
    assert result["id"] == _DETERMINISTIC_RID
    assert state["saved_signals"] is False
    assert conv["status"] == "awaiting_reply"      # NOT resolved — honest
    assert [e["event"] for e in events] == ["apply_failed"]


def test_twin_none_when_wrong_kind(monkeypatch, tmp_path):
    conv = _fp_conv(kind="spam_example_proposal")
    result, *_ = _drive_fp_apply(monkeypatch, tmp_path, conv)
    assert result is None


def test_twin_none_when_sfid_missing(monkeypatch, tmp_path):
    conv = _fp_conv()
    result, *_ = _drive_fp_apply(monkeypatch, tmp_path, conv,
                                 call_sfid="SFID-does-not-exist")
    assert result is None


def test_twin_none_when_already_resolved(monkeypatch, tmp_path):
    conv = _fp_conv(status="approved")
    result, *_ = _drive_fp_apply(monkeypatch, tmp_path, conv)
    assert result is None


def test_twin_has_no_dry_run_gate():
    """Approval must work regardless of the filter's dry_run flag — verify the
    twin genuinely never consults it (no gate to slip past)."""
    src = inspect.getsource(config_io.apply_fp_narrowing_from_pending)
    assert "dry_run" not in src


# ---------------------------------------------------------------------------
# Finding 3 — deterministic FP-narrowing id: Dashboard-Approve and email-YES
# mint the SAME R- id for one proposal, so a second apply dedupes to a single
# active rule instead of creating a duplicate.
# ---------------------------------------------------------------------------

def test_twin_applied_id_is_deterministic_from_sfid(monkeypatch, tmp_path):
    """The applied refinement id is derived from the proposal's SFID, not a
    fresh random token — 'SFID-20260704-fp01' -> 'R-20260704-fp01'."""
    conv = _fp_conv()
    result, *_ = _drive_fp_apply(monkeypatch, tmp_path, conv)
    assert result["status"] == "applied"
    assert result["id"] == _DETERMINISTIC_RID


def test_fp_id_matches_across_engine_and_app_twins():
    """The engine (email-YES) and app (Dashboard-Approve) twins derive the
    IDENTICAL id from the same conv — the property that makes the two channels
    idempotent against each other."""
    conv = _fp_conv()
    proposed = conv["proposed_changes"]
    app_ref = config_io._fp_narrowing_to_refinement(
        proposed, conv, {"ai_refinements": []}, source="dashboard")
    eng_ref = spam_filter._fp_narrowing_to_refinement(
        proposed, conv, {"ai_refinements": []}, source="email")
    assert app_ref["id"] == eng_ref["id"] == _DETERMINISTIC_RID


def test_fp_id_falls_back_to_random_when_no_sfid():
    """migrate_fp_narrowings passes conv={} (no SFID) — the id must fall back to
    a freshly minted unique R- id, never a crash, and stay unique in a batch."""
    ref = spam_filter._fp_narrowing_to_refinement(
        {"signals_to_narrow": {"from_analysis": "x"}}, {},
        {"ai_refinements": []}, source="migrated_fp_narrowing")
    assert ref["id"].startswith("R-")
    assert ref["id"] != _DETERMINISTIC_RID


def test_double_apply_same_proposal_yields_single_rule(monkeypatch, tmp_path):
    """Approve in the Dashboard AND reply YES to the same proposal before the
    next tick: the deterministic id makes the SECOND apply see the first's
    already-active rule, so exactly ONE rule exists (no duplicate)."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_paths, "PENDING_SIGNALS_PATH",
                        mem / "pending_signals.json")
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")

    conv = _fp_conv()
    # A shared signals store so apply #2 sees apply #1's write — this is the
    # cross-channel condition the deterministic id must dedupe.
    store = {"ai_refinements": []}
    monkeypatch.setattr(config_io, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": [conv]})
    monkeypatch.setattr(config_io, "save_pending_signals", lambda data: None)
    monkeypatch.setattr(config_io, "load_signals",
                        lambda: {"signals": {},
                                 "ai_refinements": list(store["ai_refinements"])})
    monkeypatch.setattr(config_io, "save_signals",
                        lambda data: store.__setitem__(
                            "ai_refinements", list(data["ai_refinements"])))
    monkeypatch.setattr(config_io, "append_refinement_log", lambda ev: None)

    r1 = config_io.apply_fp_narrowing_from_pending(conv["id"], source="dashboard")
    # The engine's per-run snapshot can't see the mid-tick Dashboard approval,
    # so it re-processes the still-"awaiting_reply" conv it loaded earlier.
    conv["status"] = "awaiting_reply"
    r2 = config_io.apply_fp_narrowing_from_pending(conv["id"], source="email")

    assert r1["status"] == "applied"
    assert r2["status"] == "already_active"
    assert r1["id"] == r2["id"] == _DETERMINISTIC_RID
    assert len(store["ai_refinements"]) == 1        # ONE rule, not two


# ---------------------------------------------------------------------------
# Parser drift-guard: the duplicated parser must match spam_filter's byte-for-byte
# ---------------------------------------------------------------------------

def test_parser_drift_guard_plain():
    assert (config_io._parse_fp_proposed_changes(FP_ANALYSIS)
            == spam_filter._parse_fp_proposed_changes(FP_ANALYSIS))


def test_parser_drift_guard_markdown_dressed():
    ours = config_io._parse_fp_proposed_changes(FP_ANALYSIS_DRESSED)
    theirs = spam_filter._parse_fp_proposed_changes(FP_ANALYSIS_DRESSED)
    assert ours == theirs
    # And the dressed analysis actually parses to something appliable (guards
    # against both parsers silently agreeing on EMPTY).
    assert config_io._fp_changes_appliable(ours)


# ---------------------------------------------------------------------------
# Dashboard handler: SignalsTab._on_approve_pending outcome -> dialog mapping.
# Never showinfo on a no-op / failure (retired / no_change / None).
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

    def askyesno(self, *a, **k):
        self.calls.append(("askyesno", a, k))
        return True


class _FakeSelf:
    def __init__(self):
        self.refreshed = False

    def refresh(self):
        self.refreshed = True


def _drive_on_approve(monkeypatch, twin_result):
    """Call SignalsTab._on_approve_pending with a bare fake self, an FP conv
    (no explicit kind -> false_positive), and a stubbed twin returning
    twin_result. Returns the messagebox capture and the fake self."""
    conv = {"id": "SFID-20260704-h1"}   # no kind -> routes to the FP branch
    msgs = _MsgCapture()
    monkeypatch.setattr(dashboard, "messagebox", msgs)
    monkeypatch.setattr(config_io, "load_pending_signals",
                        lambda: {"conversations": [conv]})
    monkeypatch.setattr(config_io, "apply_fp_narrowing_from_pending",
                        lambda sfid, source="dashboard": twin_result)
    fake = _FakeSelf()
    dashboard.SignalsTab._on_approve_pending(fake, conv["id"])
    return msgs, fake


def test_handler_applied_shows_info(monkeypatch):
    msgs, fake = _drive_on_approve(
        monkeypatch, {"status": "applied", "id": "R-1", "headline": "h"})
    assert [c[0] for c in msgs.calls] == ["showinfo"]
    assert "R-1" in msgs.calls[0][1][1]     # body names the refinement id
    assert fake.refreshed is True


def test_handler_already_active_shows_info(monkeypatch):
    msgs, fake = _drive_on_approve(
        monkeypatch, {"status": "already_active", "id": "R-1", "headline": "h"})
    assert [c[0] for c in msgs.calls] == ["showinfo"]
    assert fake.refreshed is True


def test_handler_retired_warns_never_info(monkeypatch):
    msgs, fake = _drive_on_approve(
        monkeypatch, {"status": "retired", "id": "R-1", "headline": "h"})
    kinds = [c[0] for c in msgs.calls]
    assert "showinfo" not in kinds
    assert "showwarning" in kinds
    assert fake.refreshed is True


def test_handler_no_change_errors_never_info(monkeypatch):
    msgs, fake = _drive_on_approve(monkeypatch, {"status": "no_change"})
    kinds = [c[0] for c in msgs.calls]
    assert "showinfo" not in kinds
    assert "showerror" in kinds
    assert fake.refreshed is True


def test_handler_none_errors_never_info(monkeypatch):
    msgs, fake = _drive_on_approve(monkeypatch, None)
    kinds = [c[0] for c in msgs.calls]
    assert "showinfo" not in kinds
    assert "showerror" in kinds
    assert fake.refreshed is True


def test_render_pending_card_drops_muted_fp_label_and_offers_approve():
    """The old 'reply to the email to approve' muted label is gone, and
    false_positive is now in the Approve-button set."""
    src = inspect.getsource(dashboard.SignalsTab._render_pending_card)
    assert "reply to the email" not in src
    assert '"false_positive"' in src           # folded into the Approve set
    assert "_on_approve_pending" in src


# ---------------------------------------------------------------------------
# Finding #9 — kind-aware daily-report copy
# ---------------------------------------------------------------------------

def test_pending_was_emailed_false_positive_true():
    # FP convs carry no explicit kind and no forwarder.
    assert daily_report._pending_was_emailed(
        {"id": "SFID-a", "original_subject": "x"}) is True


def test_pending_was_emailed_forward_spam_true():
    assert daily_report._pending_was_emailed(
        {"kind": "spam_example_proposal", "forwarder": "owner@x.com"}) is True


def test_pending_was_emailed_check_screen_false():
    assert daily_report._pending_was_emailed(
        {"kind": "spam_example_proposal", "forwarder": ""}) is False


def test_pending_was_emailed_block_sender_false_even_with_forwarder():
    # block_sender_proposal stamps a non-empty forwarder but is Dashboard-only;
    # kind must win over the forwarder heuristic.
    assert daily_report._pending_was_emailed(
        {"kind": "block_sender_proposal", "forwarder": "owner@x.com"}) is False


def _sig_status(active=None, expired=None):
    active = active or []
    return {"active": active, "expired": expired or [],
            "total_submitted": 0, "total_approved": 0,
            "total_rejected": 0, "total_pending": len(active)}


def test_active_line_emailed_kind_leads_with_dashboard_and_subject_search():
    conv = {"id": "SFID-20260704-e1", "expires": "2026-07-11T00:00:00",
            "original_subject": "Statement ready"}   # false_positive -> emailed
    lines = daily_report.build_pending_signals_section(_sig_status(active=[conv]))
    text = "\n".join(lines)
    assert "Dashboard" in text
    assert "Signal History" in text
    assert "in its subject line" in text
    assert "[SFID-20260704-e1]" in text
    assert "starts with" not in text             # #14: SFID is MID-subject for FP


def test_active_line_dashboard_only_kind_has_no_reply_instruction():
    conv = {"id": "SFID-20260704-d1", "expires": "2026-07-11T00:00:00",
            "original_subject": "check-screen rule",
            "kind": "spam_example_proposal", "forwarder": ""}   # dashboard-only
    lines = daily_report.build_pending_signals_section(_sig_status(active=[conv]))
    text = "\n".join(lines)
    assert "Dashboard" in text
    assert "Signal History" in text
    assert "no email to reply to" in text
    assert "reply YES" not in text               # never instruct a reply here


def test_expired_line_fp_keeps_fwd_false_positive():
    conv = {"id": "SFID-x", "original_subject": "fp thing"}   # false_positive
    lines = daily_report.build_pending_signals_section(_sig_status(expired=[conv]))
    text = "\n".join(lines)
    assert "Fwd: False Positive" in text


def test_expired_line_non_fp_points_to_check_screen_not_fwd():
    conv = {"id": "SFID-y", "original_subject": "block thing",
            "kind": "block_sender_proposal", "forwarder": "owner@x.com"}
    lines = daily_report.build_pending_signals_section(_sig_status(expired=[conv]))
    text = "\n".join(lines)
    assert "Check an Email" in text
    assert "Fwd: False Positive" not in text     # #9: never the wrong FP line

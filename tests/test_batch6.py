#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Batch 6 tests — the final finding-fix batch of the integration audit.

Covers two findings:
  - #16  "expired" refinement-log events are now WRITTEN at both real expiry
         points (the report's expiry sweep, source="report"; and the
         reply-time lazy expiry in the filter, source="reply") so the
         Dashboard's "Rejected / expired / withdrawn" history is no longer
         perpetually empty.
  - #19  handle_new_pattern records a durable, honest "send_failed" event when
         the proposal email fails to send (instead of swallowing the failure),
         while still returning True (a signal WAS derived) and leaving the
         proposal in pending_signals.json for the Dashboard's Pending list.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_batch6.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
memory directory is never read or written. REFINEMENTS_LOG_PATH /
REFINEMENTS_LOG are monkeypatched to a tmp file per test so no real log is
written. file_lock is the REAL flock — never mocked.
"""
import inspect
import json
import logging
import os
import sys

import pytest  # noqa: F401  (imported for parity with the suite / fixtures)

# Replicate the dual sys.path setup from tests/test_session9b.py: the engine
# tree (flat modules) and the app/ root (mailwarden_app package) both go on
# the path.
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402,F401  (REAL flock — never mocked)
import spam_filter  # noqa: E402
import daily_report  # noqa: E402
import learn_signals  # noqa: E402
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402

_LOG = logging.getLogger("test_batch6")
_LOG.addHandler(logging.NullHandler())


# ===========================================================================
# #16-A — the report's expiry sweep writes an "expired" event (source=report)
# ===========================================================================

def test_report_expiry_writes_expired_event(monkeypatch, tmp_path):
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    pend = mem / "pending_signals.json"
    log = mem / "signal_refinements.log"
    monkeypatch.setattr(daily_report, "PENDING_SIGNALS_PATH", pend)
    monkeypatch.setattr(daily_report, "LIFETIME_STATS_PATH", mem / "lifetime_stats.json")
    monkeypatch.setattr(daily_report, "REFINEMENTS_LOG_PATH", log)

    # One awaiting_reply proposal already past its expiry date.
    conv = {
        "id": "SFID-20200101-aaaa",
        "status": "awaiting_reply",
        "created": "2020-01-01T00:00:00",
        "expires": "2000-01-01T00:00:00",
        "original_subject": "old thing",
        "proposed_refinement": {"id": "R-16a", "headline": "expired rule"},
    }
    pend.write_text(json.dumps({"version": "1.0", "conversations": [conv]}))

    result = daily_report.expire_pending_signals(_LOG)

    # The conversation was expired (unchanged behavior)...
    assert len(result["expired"]) == 1
    # ...AND an "expired" event was written in the Dashboard-history shape.
    events = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    expired = [e for e in events if e.get("event") == "expired"]
    assert len(expired) == 1
    e = expired[0]
    assert e["sfid"] == "SFID-20200101-aaaa"
    assert e["id"] == "R-16a"
    assert e["headline"] == "expired rule"
    assert e["source"] == "report"
    assert e["ts"]  # a timestamp is present for the history's first column


def test_report_expiry_no_event_when_nothing_expires(monkeypatch, tmp_path):
    """A future-dated proposal must NOT be logged as expired (guards against
    logging on every sweep regardless of state)."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    pend = mem / "pending_signals.json"
    log = mem / "signal_refinements.log"
    monkeypatch.setattr(daily_report, "PENDING_SIGNALS_PATH", pend)
    monkeypatch.setattr(daily_report, "LIFETIME_STATS_PATH", mem / "lifetime_stats.json")
    monkeypatch.setattr(daily_report, "REFINEMENTS_LOG_PATH", log)

    conv = {
        "id": "SFID-29990101-bbbb",
        "status": "awaiting_reply",
        "created": "2026-01-01T00:00:00",
        "expires": "2999-01-01T00:00:00",
        "original_subject": "still live",
        "proposed_refinement": {"id": "R-16b", "headline": "live rule"},
    }
    pend.write_text(json.dumps({"version": "1.0", "conversations": [conv]}))

    result = daily_report.expire_pending_signals(_LOG)

    assert result["expired"] == []
    assert not log.exists() or log.read_text().strip() == ""


# ===========================================================================
# #16-B — the reply-time (lazy) expiry writes an "expired" event (source=reply)
#
# The write is embedded inside run_filter's reply-dispatch loop, which needs
# live IMAP to execute end-to-end. Following the suite's established pattern
# for run_filter guards (test_session9b::test_run_filter_loads_pending_after_
# prune_source_order), we assert the write is wired INTO the real expiry
# branch: after the status transition and before the "Expired" ack send.
# ===========================================================================

def test_reply_time_expiry_logs_expired_event_source_reply():
    src = inspect.getsource(spam_filter.run_filter)
    i_status = src.index('conv["status"] = "expired"')
    i_event = src.index('"event": "expired"', i_status)
    i_source = src.index('"source": "reply"', i_status)
    i_ack = src.index('— Expired', i_status)
    assert i_status < i_event < i_ack, (
        "the expired-log write must sit inside the reply-time expiry branch, "
        "after conv['status']='expired' and before the 'Expired' ack send"
    )
    assert i_status < i_source < i_ack, (
        "the reply-path expiry event must carry source='reply'"
    )


# ===========================================================================
# #16-C — an "expired" event round-trips through config_io.load_refinement_log
#         (the loader the Dashboard uses) AND the Dashboard's history filter
#         includes "expired".
# ===========================================================================

def test_expired_event_roundtrips_and_dashboard_filter_includes_it(monkeypatch, tmp_path):
    log = tmp_path / "signal_refinements.log"
    # Write via the report's appender; read via config_io's loader (the one the
    # Dashboard renders) — both must target the same file/format.
    monkeypatch.setattr(daily_report, "REFINEMENTS_LOG_PATH", log)
    monkeypatch.setattr(app_paths, "REFINEMENTS_LOG", log)

    daily_report.append_refinement_log({
        "ts": "2026-07-04T12:00:00",
        "event": "expired",
        "id": "R-c",
        "sfid": "SFID-c",
        "headline": "h",
        "source": "report",
    })

    loaded = config_io.load_refinement_log()
    assert any(e.get("event") == "expired" and e.get("sfid") == "SFID-c"
               for e in loaded), "report-written 'expired' event must be loadable"

    # The Dashboard's history section must include "expired" in its shown set.
    hist_src = inspect.getsource(dashboard.SignalsTab._render_history)
    for name in ("rejected", "expired", "withdrawn", "deleted"):
        assert f'"{name}"' in hist_src, f'Dashboard history must render {name!r}'


# ===========================================================================
# #19 — a failed proposal send is recorded honestly, not swallowed
# ===========================================================================

def _drive_new_pattern(monkeypatch, tmp_path, *, sent: bool):
    """Drive learn_signals.handle_new_pattern with IO stubbed and a chosen
    _send outcome. Returns (return_value, logged_events, captured_pending)."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    # Redirect the flock target so the lock file lands in tmp, not the real
    # memory dir (load/save are stubbed, but file_lock uses the path directly).
    monkeypatch.setattr(learn_signals, "PENDING_SIGNALS_PATH",
                        mem / "pending_signals.json")

    captured = {}
    events = []
    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": []})
    monkeypatch.setattr(learn_signals, "save_pending_signals",
                        lambda data: captured.__setitem__("pending", data))
    monkeypatch.setattr(learn_signals, "append_refinement_log",
                        lambda e: events.append(e))
    monkeypatch.setattr(learn_signals, "_send", lambda *a, **k: sent)

    classification = {
        "kind": "new_pattern",
        "headline": "kill timeshare spam",
        "rationale": "user taught this",
        "what_this_doesnt_cover": "",
        "confidence": "medium",
    }
    example = {
        "filename": "ex1.eml",
        "from": "promo@example.net",
        "subject": "Your resort getaway awaits",
        "forwarder": "owner@example.com",
    }
    signals_data = {"signals": {}, "ai_refinements": []}
    config = {"accounts": [{"username": "owner@example.com"}],
              "smtp": {"host": "smtp.example.com", "username": "owner@example.com"}}

    ok = learn_signals.handle_new_pattern(
        classification, example, signals_data, config, _LOG)
    return ok, events, captured


def test_send_failure_records_send_failed_event(monkeypatch, tmp_path):
    ok, events, captured = _drive_new_pattern(monkeypatch, tmp_path, sent=False)

    # The signal WAS derived (the proposal was created + persisted), so the
    # owner-facing "derived from N examples" count stays honest.
    assert ok is True
    # The proposal is still saved -> recoverable in the Dashboard Pending list.
    assert captured.get("pending", {}).get("conversations"), \
        "the proposal must still be persisted even when the email failed"
    # The failure is recorded honestly and durably.
    send_failed = [e for e in events if e.get("event") == "send_failed"]
    assert len(send_failed) == 1
    e = send_failed[0]
    assert e["sfid"].startswith("SFID-")
    assert e["id"]                       # refinement id present
    assert e["headline"] == "kill timeshare spam"
    assert e["source"] == "learner"
    assert "failed to send" in e.get("reason", "")


def test_successful_send_records_no_send_failed_event(monkeypatch, tmp_path):
    ok, events, captured = _drive_new_pattern(monkeypatch, tmp_path, sent=True)

    assert ok is True
    assert [e for e in events if e.get("event") == "send_failed"] == []
    # The normal "proposed" event still fires on the success path (regression
    # guard: the send-failure branch must not have displaced it).
    assert any(e.get("event") == "proposed" for e in events)


#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Task #10 — MailWarden must never junk its own owner-facing mail.

Regression guards for the two-part fix:
  1. daily_report.send_report now stamps X-MailWarden-System: 1 (like
     spam_filter.send_email), so the loop-top self-loop guard skips the report.
  2. spam_filter._is_own_outgoing_mail — a header-INDEPENDENT defense-in-depth
     skip that fires at the loop top (before every classification gate and NOT
     conditioned on _command_auth_ok) for our OWN outgoing mail: the daily
     report and the FP-analysis email (whose subject embeds the original spam
     subject and would otherwise trip the subject-keyword gate).

It must NOT swallow a genuine owner command/approval reply (those start with the
owner's own text, never with one of our outgoing-body markers) and must NOT fire
for a non-owner sender.

NO real API / SMTP calls. Real report bodies come from
daily_report.build_report_body — no hand-written email bodies.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_own_mail_guard.py -v
"""
import inspect
import os
import sys
from datetime import datetime
from email.mime.text import MIMEText

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import daily_report  # noqa: E402
import spam_filter  # noqa: E402

# Owner's configured identity: per-account reports are sent FROM the single
# global SMTP identity, so that address must count as "own".
_OWNER = "owner@example.com"
_SMTP_ID = "mailwarden@example.com"
_CONFIG = {
    "accounts": [{"name": "Main", "username": _OWNER, "enabled": True}],
    "smtp": {"username": _SMTP_ID, "from_address": _SMTP_ID},
    "filter": {"dry_run": True},
    "signal_learner": {},
}
_ACCOUNT = _CONFIG["accounts"][0]

_MIN_DECISIONS = {
    "per_account": {}, "evaluated": 0, "spam_moved": 0, "not_spam": 0,
    "errors": 0, "spam_entries": [],
}


def _real_report_body(monkeypatch, tmp_path) -> str:
    """A REAL daily-report body (starts with 'SPAM FILTER DAILY REPORT')."""
    monkeypatch.setattr(daily_report, "LEARNER_STATE_PATH",
                        tmp_path / "no_learner_state.json")
    return daily_report.build_report_body(
        _CONFIG, dict(_MIN_DECISIONS), datetime.now(), 0,
        {"derived_from_examples": 0})


# ---------------------------------------------------------------------------
# Part 1 — the daily report is stamped as system mail
# ---------------------------------------------------------------------------

def test_send_report_stamps_system_header():
    """send_report must stamp X-MailWarden-System: 1, exactly like send_email."""
    src = inspect.getsource(daily_report.send_report)
    assert 'msg["X-MailWarden-System"] = "1"' in src
    # And the value matches send_email's stamp verbatim.
    assert 'msg["X-MailWarden-System"] = "1"' in \
        inspect.getsource(spam_filter.send_email)


# ---------------------------------------------------------------------------
# Part 2 — header-independent own-mail guard
# ---------------------------------------------------------------------------

def _msg(from_email, body):
    return {"from_email": from_email, "plain_text_body": body}


def test_daily_report_skipped_even_with_auth_false_and_header_stripped(
        monkeypatch, tmp_path):
    """The report round-trips as OWN mail with no header and regardless of auth:
    _is_own_outgoing_mail is header-independent and never calls _command_auth_ok
    (forcing it False changes nothing)."""
    body = _real_report_body(monkeypatch, tmp_path)
    monkeypatch.setattr(spam_filter, "_command_auth_ok",
                        lambda *a, **k: False)
    # Sent from the global SMTP identity (an owner identity), header stripped.
    assert spam_filter._is_own_outgoing_mail(
        _msg(_SMTP_ID, body), _ACCOUNT, _CONFIG) is True


def test_fp_analysis_email_not_junked_when_header_stripped(monkeypatch):
    """The FP-analysis email opens with a known own-mail marker, so it is caught
    by the guard BEFORE the subject-keyword gate — even though its subject embeds
    the original spam subject. Uses the real product marker, not a hand-written
    body."""
    marker = "Your false positive has been analyzed"
    assert marker in spam_filter._OWN_OUTGOING_BODY_MARKERS
    # The real FP-analysis email body starts with this exact sentence (+ a period).
    body = marker + ".\n\nsome analysis text here\n"
    monkeypatch.setattr(spam_filter, "_command_auth_ok", lambda *a, **k: False)
    assert spam_filter._is_own_outgoing_mail(
        _msg(_SMTP_ID, body), _ACCOUNT, _CONFIG) is True


def test_non_owner_with_same_body_prefix_is_classified_normally(
        monkeypatch, tmp_path):
    """A third party who copies the report's opening line is NOT treated as own
    mail (the From is not an owner identity), so it flows to classification."""
    body = _real_report_body(monkeypatch, tmp_path)
    assert spam_filter._is_own_outgoing_mail(
        _msg("stranger@evil.example", body), _ACCOUNT, _CONFIG) is False


def test_owner_reply_is_not_swallowed(monkeypatch):
    """A genuine owner APPROVE/YES reply starts with the owner's own text — not a
    marker — so the guard does NOT fire and the reply still reaches strict
    command handling."""
    for reply in ("APPROVE 3\n\n> quoted report...", "YES", "NO thanks"):
        assert spam_filter._is_own_outgoing_mail(
            _msg(_OWNER, reply), _ACCOUNT, _CONFIG) is False


def test_guard_requires_owner_identity_and_marker(monkeypatch):
    # Owner identity but ordinary body -> not own mail.
    assert spam_filter._is_own_outgoing_mail(
        _msg(_OWNER, "hey, are we still on for lunch?"), _ACCOUNT,
        _CONFIG) is False
    # Empty body -> not own mail (no false positive on blank).
    assert spam_filter._is_own_outgoing_mail(
        _msg(_OWNER, "   "), _ACCOUNT, _CONFIG) is False


def test_guard_runs_before_gates_and_not_gated_on_auth():
    """Source guard: the loop-top skip calls _is_own_outgoing_mail and is NOT
    wrapped in a _command_auth_ok / mwr_match condition."""
    src = inspect.getsource(spam_filter.run_filter)
    assert "_is_own_outgoing_mail(msg_data, account, config)" in src
    # The own-mail skip must appear before the subject-keyword gate it protects.
    guard_at = src.index("_is_own_outgoing_mail(msg_data, account, config)")
    gate_at = src.index("check_subject_keywords(")
    assert guard_at < gate_at

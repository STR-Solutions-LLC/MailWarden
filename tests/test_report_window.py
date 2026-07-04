#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Per-account calendar-day report window + watermark tests (audit Session 9A,
finding C10), plus the SMTP retry (Task 2) and the dead-code deletions (Task 4).

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_report_window.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
directory is never read or written. The module-level *_PATH constants are
monkeypatched to point at tmp copies (the suite's convention for redirecting
engine IO). file_lock is the REAL flock — never mocked.
"""
import json
import logging
import os
import smtplib
import sys
from datetime import datetime, timedelta

import pytest

# Replicate the dual sys.path setup from tests/test_fixes.py: the engine tree
# (flat modules) and the app/ root (mailwarden_app package) both go on the path.
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402  (REAL flock — never mocked)
import daily_report  # noqa: E402
import utils  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dt(s):
    """Parse 'YYYY-MM-DD HH:MM:SS' into a naive datetime."""
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def _decisions_log(*entries):
    """Join decision entries with the canonical '  ---\\n' separator."""
    return "  ---\n".join(entries) + "  ---\n"


def _bl_entry(ts, acct="A", addr="x@bad.com", subject="s"):
    return (f"[{ts}] ACCOUNT: {acct}\n"
            f"FROM: {addr}\n"
            f"SUBJECT: {subject}\n"
            f'DECISION: BLACKLISTED (matched address: "{addr}")')


def _wl_entry(ts, acct="A", addr="f@good.com"):
    return (f"[{ts}] ACCOUNT: {acct}\n"
            f"FROM: {addr}\n"
            f"DECISION: WHITELISTED")


def _spam_entry(ts, acct="A", addr="s@bad.com", subject="buy"):
    return (f"[{ts}] ACCOUNT: {acct}\n"
            f"FROM: {addr}\n"
            f"SUBJECT: {subject}\n"
            f"DECISION: spam — MOVED to Junk (confidence: 0.95)")


# ===========================================================================
# A) Pure window unit tests — no mocking, `now` passed explicitly.
# ===========================================================================

def test_a_most_recent_boundary_just_before_8am():
    now = _dt("2026-06-19 07:59:59")
    assert daily_report.most_recent_boundary(now) == _dt("2026-06-18 08:00:00")


def test_a_most_recent_boundary_exactly_8am():
    now = _dt("2026-06-19 08:00:00")
    assert daily_report.most_recent_boundary(now) == _dt("2026-06-19 08:00:00")


def test_a_most_recent_boundary_evening():
    now = _dt("2026-06-19 23:00:00")
    assert daily_report.most_recent_boundary(now) == _dt("2026-06-19 08:00:00")


def test_a_on_time_8am_first_run():
    """First run (watermark None) exactly at 08:00 covers the prior complete day."""
    now = _dt("2026-06-19 08:00:00")
    start, end = daily_report.compute_report_window(now, None)
    assert end == _dt("2026-06-19 08:00:00")
    assert start == _dt("2026-06-18 08:00:00")


def test_a_asleep_until_midday_no_gap():
    """Machine asleep past 08:00, ran at midday: same prior-day window, no gap."""
    now = _dt("2026-06-19 12:30:00")
    watermark = _dt("2026-06-18 08:00:00")
    start, end = daily_report.compute_report_window(now, watermark)
    assert start == _dt("2026-06-18 08:00:00")
    assert end == _dt("2026-06-19 08:00:00")


def test_a_multi_day_catch_up():
    """Missed several days: window spans watermark..most-recent-boundary."""
    now = _dt("2026-06-19 10:00:00")
    watermark = _dt("2026-06-15 08:00:00")
    start, end = daily_report.compute_report_window(now, watermark)
    assert start == _dt("2026-06-15 08:00:00")
    assert end == _dt("2026-06-19 08:00:00")
    assert (end - start).days == 4


def test_a_first_run_none_at_10am():
    """First run at 10:00 → covers the last complete day (yesterday 08:00..today 08:00)."""
    now = _dt("2026-06-19 10:00:00")
    start, end = daily_report.compute_report_window(now, None)
    assert start == _dt("2026-06-18 08:00:00")
    assert end == _dt("2026-06-19 08:00:00")


def test_a_first_run_before_8am():
    """First run before 08:00 → boundary is yesterday 08:00, covers day before."""
    now = _dt("2026-06-19 06:00:00")
    start, end = daily_report.compute_report_window(now, None)
    assert end == _dt("2026-06-18 08:00:00")
    assert start == _dt("2026-06-17 08:00:00")


def test_a_empty_window_same_day_rerun():
    """Re-run after already reporting through today's boundary → start == end."""
    now = _dt("2026-06-19 15:00:00")
    watermark = _dt("2026-06-19 08:00:00")
    start, end = daily_report.compute_report_window(now, watermark)
    assert start == end == _dt("2026-06-19 08:00:00")


def test_a_clock_rewind_watermark_in_future_clamps():
    """Watermark ahead of the boundary (clock rewind) clamps to empty, not negative."""
    now = _dt("2026-06-19 09:00:00")
    watermark = _dt("2026-06-25 08:00:00")  # in the future
    start, end = daily_report.compute_report_window(now, watermark)
    assert end == _dt("2026-06-19 08:00:00")
    assert start == end  # clamped


def test_a_dst_spring_forward():
    """2026-03-08 is US spring-forward (a 23h day). Naive calendar arithmetic
    still maps to that date's 08:00 — no off-by-an-hour."""
    now = _dt("2026-03-08 09:00:00")
    watermark = _dt("2026-03-07 08:00:00")
    start, end = daily_report.compute_report_window(now, watermark)
    assert start == _dt("2026-03-07 08:00:00")
    assert end == _dt("2026-03-08 08:00:00")


def test_a_dst_fall_back():
    """2026-11-01 is US fall-back (a 25h day). Same: maps to that date's 08:00."""
    now = _dt("2026-11-01 10:00:00")
    watermark = _dt("2026-10-31 08:00:00")
    start, end = daily_report.compute_report_window(now, watermark)
    assert start == _dt("2026-10-31 08:00:00")
    assert end == _dt("2026-11-01 08:00:00")


def test_a_parse_state_ts():
    assert daily_report._parse_state_ts(None) is None
    assert daily_report._parse_state_ts("") is None
    assert daily_report._parse_state_ts("garbage") is None
    assert daily_report._parse_state_ts("2026-06-19T08:00:00") == _dt("2026-06-19 08:00:00")


# ===========================================================================
# B) Scanner half-open windowing — entry AT window_start included,
#    entry AT window_end EXCLUDED. file_lock untouched (these are pure reads).
# ===========================================================================

@pytest.fixture
def window():
    return _dt("2026-06-18 08:00:00"), _dt("2026-06-19 08:00:00")


def _put_decisions(monkeypatch, tmp_path, content):
    p = tmp_path / "decisions.log"
    p.write_text(content)
    monkeypatch.setattr(daily_report, "DECISIONS_LOG_PATH", p)
    return p


def test_b_blacklist_half_open(monkeypatch, tmp_path, window):
    start, end = window
    at_start = start.strftime("%Y-%m-%d %H:%M:%S")
    at_end = end.strftime("%Y-%m-%d %H:%M:%S")
    inside = (start + timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        _bl_entry(at_start, addr="atstart@bad.com"),
        _bl_entry(inside, addr="inside@bad.com"),
        _bl_entry(at_end, addr="atend@bad.com"),
    ))
    count, entries = daily_report.count_blacklisted_blocked_24h(start, end)
    froms = {e["from"] for e in entries}
    assert count == 2
    assert "atstart@bad.com" in froms      # window_start INCLUDED
    assert "inside@bad.com" in froms
    assert "atend@bad.com" not in froms     # window_end EXCLUDED


def test_b_whitelist_half_open(monkeypatch, tmp_path, window):
    start, end = window
    at_start = start.strftime("%Y-%m-%d %H:%M:%S")
    at_end = end.strftime("%Y-%m-%d %H:%M:%S")
    inside = (start + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        _wl_entry(at_start),
        _wl_entry(inside),
        _wl_entry(at_end),
    ))
    count = daily_report.count_whitelisted_passthrough_24h(start, end)
    assert count == 2  # at_start in, at_end out


def test_b_parse_decisions_half_open(monkeypatch, tmp_path, window):
    start, end = window
    at_start = start.strftime("%Y-%m-%d %H:%M:%S")
    at_end = end.strftime("%Y-%m-%d %H:%M:%S")
    inside = (start + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        _spam_entry(at_start, subject="buy-start"),
        _spam_entry(inside, subject="buy-inside"),
        _spam_entry(at_end, subject="buy-end"),
    ))
    result = daily_report.parse_decisions_24h(start, end)
    # Only the two in [start, end) count.
    assert result["spam_moved"] == 2
    subjects = {e["subject"] for e in result["spam_entries"]}
    assert "buy-start" in subjects
    assert "buy-inside" in subjects
    assert "buy-end" not in subjects


def test_b_get_last_filter_run_windowed_but_last_run_absolute(monkeypatch, tmp_path, window):
    start, end = window
    # Build an operational log: a run inside the window, an ERROR inside, and a
    # MUCH more recent run AFTER window_end (which must still be last_run, ABS).
    inside_run = (start + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    inside_err = (start + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    at_end_run = end.strftime("%Y-%m-%d %H:%M:%S")  # EXCLUDED from counts
    after_end_run = (end + timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S")
    after_end_err = (end + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")
    log = (
        f"{inside_run} Spam filter starting\n"
        f"{inside_err} [ERROR] boom\n"
        f"{at_end_run} Spam filter starting\n"
        f"{after_end_run} Spam filter starting\n"
        f"{after_end_err} [ERROR] boom\n"
    )
    p = tmp_path / "spam_filter.log"
    p.write_text(log)
    monkeypatch.setattr(daily_report, "LOG_PATH", p)

    last_run, runs, errors = daily_report.get_last_filter_run(start, end)
    # last_run is the ABSOLUTE most-recent "Spam filter starting", even past end.
    assert last_run == _dt(after_end_run)
    # Only the inside run/error are within [start, end). The at_end run is
    # excluded (half-open), the after-end run/error are out of window.
    assert runs == 1
    assert errors == 1


# ===========================================================================
# C) main() integration via main(now=...).
# ===========================================================================

@pytest.fixture
def main_env(tmp_path, monkeypatch):
    """Redirect every daily_report data path into tmp and stub the heavy/IO
    collaborators so main() exercises ONLY the window/watermark machinery."""
    mem = tmp_path / "memory"
    logs = tmp_path / "logs"
    mem.mkdir()
    logs.mkdir()

    paths = {
        "TOKEN_USAGE_PATH": mem / "token_usage.json",
        "REPORT_STATE_PATH": mem / "report_state.json",
        "DECISIONS_LOG_PATH": mem / "decisions.log",
        "LOG_PATH": logs / "spam_filter.log",
        "WHITELIST_PATH": mem / "whitelist.json",
        "BLACKLIST_PATH": mem / "blacklist.json",
        "SIGNALS_PATH": mem / "signals.json",
        "PENDING_SIGNALS_PATH": mem / "pending_signals.json",
        "LEARNER_STATE_PATH": mem / "learner_state.json",
    }
    for attr, p in paths.items():
        monkeypatch.setattr(daily_report, attr, p)

    # Seed the files the unstubbed code paths read.
    paths["TOKEN_USAGE_PATH"].write_text(json.dumps({
        "version": "1.0", "last_updated": "",
        "lifetime_input_tokens": 0, "lifetime_output_tokens": 0,
        "lifetime_api_calls": 0, "daily_records": [],
    }))
    paths["DECISIONS_LOG_PATH"].write_text("")
    paths["LOG_PATH"].write_text("")

    monkeypatch.setattr(daily_report, "setup_logging",
                        lambda: logging.getLogger("daily_report_test"))
    monkeypatch.setattr(daily_report, "build_report_body",
                        lambda *a, **k: "BODY")
    monkeypatch.setattr(daily_report, "expire_pending_signals",
                        lambda logger: {})
    monkeypatch.setattr(daily_report, "load_signals", lambda: {})
    monkeypatch.setattr(daily_report, "load_whitelist",
                        lambda: {"domains": []})
    monkeypatch.setattr(daily_report, "load_blacklist",
                        lambda: {"addresses": [], "display_names": []})

    return tmp_path, paths


def _seed_config(monkeypatch, accounts, dry_run=True):
    cfg = {
        "accounts": accounts,
        "filter": {"dry_run": dry_run},
        "anthropic": {"api_key": "k", "model": ""},
        "smtp": {"host": "h", "port": 587, "username": "u@x.com"},
        "summary": {"recipient": "owner@x.com"},
    }
    monkeypatch.setattr(daily_report, "load_config", lambda: cfg)
    return cfg


def _record_sends(monkeypatch, fail_for=()):
    """Stub send_report; record (subject, to_addr). Raise for to_addrs in
    fail_for to simulate per-account SMTP failure."""
    sent = []

    def _send(config, subject, body, logger, to_addr=""):
        if to_addr in fail_for:
            raise RuntimeError(f"smtp boom for {to_addr}")
        sent.append({"subject": subject, "to": to_addr})

    monkeypatch.setattr(daily_report, "send_report", _send)
    return sent


def test_c_happy_path_advances_watermark(main_env, monkeypatch):
    tmp_path, paths = main_env
    now = _dt("2026-06-19 10:00:00")
    yesterday_boundary = _dt("2026-06-18 08:00:00")
    today_boundary = _dt("2026-06-19 08:00:00")

    _seed_config(monkeypatch, [
        {"name": "A", "username": "a@x.com", "enabled": True}])
    # Pre-existing watermark = day before, so the window is non-empty.
    paths["REPORT_STATE_PATH"].write_text(json.dumps({
        "accounts": {"A": {"last_report_through": yesterday_boundary.isoformat()}}}))
    sent = _record_sends(monkeypatch)

    daily_report.main(now=now)

    assert len(sent) == 1 and sent[0]["to"] == "a@x.com"
    state = json.loads(paths["REPORT_STATE_PATH"].read_text())
    acct = state["accounts"]["A"]
    assert acct["last_report_through"] == today_boundary.isoformat()
    assert "last_success_at" in acct


def test_c_d_send_failure_watermark_unchanged(main_env, monkeypatch):
    tmp_path, paths = main_env
    now = _dt("2026-06-19 10:00:00")
    yesterday_boundary = _dt("2026-06-18 08:00:00")

    _seed_config(monkeypatch, [
        {"name": "A", "username": "a@x.com", "enabled": True}])
    orig = {"accounts": {"A": {
        "last_report_through": yesterday_boundary.isoformat()}}}
    paths["REPORT_STATE_PATH"].write_text(json.dumps(orig))
    _record_sends(monkeypatch, fail_for=("a@x.com",))

    daily_report.main(now=now)

    state = json.loads(paths["REPORT_STATE_PATH"].read_text())
    acct = state["accounts"]["A"]
    # Watermark UNCHANGED, no last_success_at written.
    assert acct["last_report_through"] == yesterday_boundary.isoformat()
    assert "last_success_at" not in acct


def test_c_g_already_reported_today_no_send(main_env, monkeypatch):
    tmp_path, paths = main_env
    now = _dt("2026-06-19 15:00:00")
    today_boundary = _dt("2026-06-19 08:00:00")

    _seed_config(monkeypatch, [
        {"name": "A", "username": "a@x.com", "enabled": True}])
    # Watermark already AT today's 08:00 → empty window → skip.
    paths["REPORT_STATE_PATH"].write_text(json.dumps({
        "accounts": {"A": {"last_report_through": today_boundary.isoformat()}}}))
    sent = _record_sends(monkeypatch)

    daily_report.main(now=now)

    assert sent == []  # send_report NOT called
    state = json.loads(paths["REPORT_STATE_PATH"].read_text())
    # Untouched.
    assert state["accounts"]["A"]["last_report_through"] == today_boundary.isoformat()
    assert "last_success_at" not in state["accounts"]["A"]


def test_c_per_account_isolation(main_env, monkeypatch):
    """A and B both due; B's send fails → A advances, B untouched."""
    tmp_path, paths = main_env
    now = _dt("2026-06-19 10:00:00")
    yesterday_boundary = _dt("2026-06-18 08:00:00")
    today_boundary = _dt("2026-06-19 08:00:00")

    _seed_config(monkeypatch, [
        {"name": "A", "username": "a@x.com", "enabled": True},
        {"name": "B", "username": "b@x.com", "enabled": True}])
    paths["REPORT_STATE_PATH"].write_text(json.dumps({"accounts": {
        "A": {"last_report_through": yesterday_boundary.isoformat()},
        "B": {"last_report_through": yesterday_boundary.isoformat()},
    }}))
    sent = _record_sends(monkeypatch, fail_for=("b@x.com",))

    daily_report.main(now=now)

    tos = {s["to"] for s in sent}
    assert tos == {"a@x.com"}  # only A actually sent
    state = json.loads(paths["REPORT_STATE_PATH"].read_text())
    # A advanced, B untouched.
    assert state["accounts"]["A"]["last_report_through"] == today_boundary.isoformat()
    assert "last_success_at" in state["accounts"]["A"]
    assert state["accounts"]["B"]["last_report_through"] == yesterday_boundary.isoformat()
    assert "last_success_at" not in state["accounts"]["B"]


def test_c_new_account_first_run(main_env, monkeypatch):
    """No report_state.json file at all → first-run window, sends, establishes
    watermark at today's 08:00."""
    tmp_path, paths = main_env
    now = _dt("2026-06-19 10:00:00")
    today_boundary = _dt("2026-06-19 08:00:00")

    _seed_config(monkeypatch, [
        {"name": "A", "username": "a@x.com", "enabled": True}])
    # Deliberately do NOT create REPORT_STATE_PATH.
    assert not paths["REPORT_STATE_PATH"].exists()
    sent = _record_sends(monkeypatch)

    daily_report.main(now=now)

    assert len(sent) == 1
    state = json.loads(paths["REPORT_STATE_PATH"].read_text())
    acct = state["accounts"]["A"]
    assert acct["last_report_through"] == today_boundary.isoformat()
    assert "last_success_at" in acct


def test_c_already_reported_account_skipped_among_due(main_env, monkeypatch):
    """One account already reported (skipped), another due (sent)."""
    tmp_path, paths = main_env
    now = _dt("2026-06-19 10:00:00")
    yesterday_boundary = _dt("2026-06-18 08:00:00")
    today_boundary = _dt("2026-06-19 08:00:00")

    _seed_config(monkeypatch, [
        {"name": "A", "username": "a@x.com", "enabled": True},
        {"name": "B", "username": "b@x.com", "enabled": True}])
    paths["REPORT_STATE_PATH"].write_text(json.dumps({"accounts": {
        "A": {"last_report_through": today_boundary.isoformat()},      # done
        "B": {"last_report_through": yesterday_boundary.isoformat()},  # due
    }}))
    sent = _record_sends(monkeypatch)

    daily_report.main(now=now)

    assert {s["to"] for s in sent} == {"b@x.com"}  # only B sent; A skipped
    state = json.loads(paths["REPORT_STATE_PATH"].read_text())
    assert state["accounts"]["A"]["last_report_through"] == today_boundary.isoformat()
    assert "last_success_at" not in state["accounts"]["A"]
    assert state["accounts"]["B"]["last_report_through"] == today_boundary.isoformat()
    assert "last_success_at" in state["accounts"]["B"]


# ===========================================================================
# D) Task 2 — SMTP retry in send_report.
# ===========================================================================

class _FakeServer:
    def __init__(self):
        self.sent = 0

    def sendmail(self, from_addr, to_addrs, msg):
        self.sent += 1

    def quit(self):
        pass


@pytest.fixture
def smtp_config():
    return {
        "smtp": {"host": "h", "port": 587, "username": "u@x.com",
                 "from_address": "u@x.com"},
        "summary": {"recipient": "owner@x.com"},
    }


def test_d_transient_then_success_retries(monkeypatch, smtp_config):
    """Two transient disconnects, then a working server → smtp_login called 3×,
    sendmail once."""
    calls = {"login": 0}
    server = _FakeServer()

    def _login(cfg):
        calls["login"] += 1
        if calls["login"] < 3:
            raise smtplib.SMTPServerDisconnected("dropped")
        return server

    monkeypatch.setattr(utils, "smtp_login", _login)
    monkeypatch.setattr(daily_report.time, "sleep", lambda *_a, **_k: None)

    logger = logging.getLogger("retry_test")
    daily_report.send_report(smtp_config, "subj", "body", logger)

    assert calls["login"] == 3
    assert server.sent == 1


def test_d_transient_always_raises_after_3(monkeypatch, smtp_config):
    """Transient failure on every attempt → raises after exactly 3 logins."""
    calls = {"login": 0}

    def _login(cfg):
        calls["login"] += 1
        raise smtplib.SMTPServerDisconnected("always down")

    monkeypatch.setattr(utils, "smtp_login", _login)
    monkeypatch.setattr(daily_report.time, "sleep", lambda *_a, **_k: None)

    logger = logging.getLogger("retry_test")
    with pytest.raises(smtplib.SMTPServerDisconnected):
        daily_report.send_report(smtp_config, "subj", "body", logger)

    assert calls["login"] == 3


def test_d_permanent_raises_immediately_no_retry(monkeypatch, smtp_config):
    """A permanent auth error raises on the FIRST attempt — NO retry."""
    calls = {"login": 0}

    def _login(cfg):
        calls["login"] += 1
        raise smtplib.SMTPAuthenticationError(535, b"bad creds")

    monkeypatch.setattr(utils, "smtp_login", _login)
    slept = {"n": 0}
    monkeypatch.setattr(daily_report.time, "sleep",
                        lambda *_a, **_k: slept.__setitem__("n", slept["n"] + 1))

    logger = logging.getLogger("retry_test")
    with pytest.raises(smtplib.SMTPAuthenticationError):
        daily_report.send_report(smtp_config, "subj", "body", logger)

    assert calls["login"] == 1  # no retry
    assert slept["n"] == 0      # never slept


# ===========================================================================
# E) Task 4 — dead code deleted, keepers retained.
# ===========================================================================

def test_e_dead_functions_removed():
    for name in ("get_blacklist_dir", "detect_imap_separator",
                 "get_imap_root_prefix", "parse_folder_name",
                 "ensure_blacklist_folders", "process_imap_blacklist_folders",
                 "process_filesystem_blacklist_folders",
                 "sync_display_names_txt"):
        assert not hasattr(daily_report, name), f"{name} should be deleted"


def test_e_keepers_retained():
    for name in ("load_blacklist", "save_blacklist",
                 "count_blacklisted_blocked_24h"):
        assert hasattr(daily_report, name), f"{name} must remain"


# ===========================================================================
# F) Finding #12 — legacy duplicate suppression in parse_decisions_24h.
#    The pre-fix dry-run filter re-logged the same UNSEEN spam every tick;
#    exact repeats (same MESSAGE-ID, same dry/real kind) must collapse to ONE
#    numbered entry / ONE counter contribution, while a dry-run preview and a
#    later real MOVED record for the same message (the normal Dry Run -> real
#    transition) must BOTH remain visible. Records without exactly one
#    MESSAGE-ID line are non-dedupable (counted exactly as before).
# ===========================================================================

def _ai_spam_entry(ts, msg_id, acct="A", addr="s@bad.com", subject="buy",
                   dry=True):
    action = ("[DRY RUN - would move to Junk]" if dry else "MOVED to Junk")
    return (f"[{ts}] ACCOUNT: {acct}\n"
            f"  MESSAGE-ID: {msg_id}\n"
            f"  FROM: Seller <{addr}>\n"
            f"  SUBJECT: {subject}\n"
            f"  DECISION: SPAM (confidence: 0.95)\n"
            f"  SIGNALS HIT: s1\n"
            f"  ACTION: {action}")


def test_f_duplicate_dry_run_records_collapse_to_one(monkeypatch, tmp_path,
                                                     window):
    start, end = window
    ts = (start + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        *[_ai_spam_entry(ts, "<loop@x>", dry=True) for _ in range(5)]))

    result = daily_report.parse_decisions_24h(start, end)
    assert len(result["spam_entries"]) == 1, (
        "5 exact repeats -> ONE numbered entry (one APPROVE token)")
    assert result["spam_dry_run"] == 1, "counter must match the list"
    assert result["evaluated"] == 1
    assert result["per_account"]["A"]["spam_dry_run"] == 1
    assert result["per_account"]["A"]["evaluated"] == 1


def test_f_distinct_messages_not_collapsed(monkeypatch, tmp_path, window):
    start, end = window
    ts = (start + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        _ai_spam_entry(ts, "<m1@x>", subject="one", dry=True),
        _ai_spam_entry(ts, "<m2@x>", subject="two", dry=True)))

    result = daily_report.parse_decisions_24h(start, end)
    assert len(result["spam_entries"]) == 2
    assert result["spam_dry_run"] == 2


def test_f_dry_then_real_transition_keeps_both(monkeypatch, tmp_path, window):
    # Dry Run preview record + the later real MOVED record for the SAME
    # message: kind is part of the dedup key, so both stay visible.
    start, end = window
    t1 = (start + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    t2 = (start + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        _ai_spam_entry(t1, "<trans@x>", dry=True),
        _ai_spam_entry(t2, "<trans@x>", dry=False)))

    result = daily_report.parse_decisions_24h(start, end)
    assert result["spam_dry_run"] == 1
    assert result["spam_moved"] == 1
    assert len(result["spam_entries"]) == 2


def test_f_no_message_id_is_non_dedupable(monkeypatch, tmp_path, window):
    # Exactly-one discipline: the legacy fixture records (no MESSAGE-ID line)
    # keep counting individually, exactly as before the fix.
    start, end = window
    ts = (start + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    _put_decisions(monkeypatch, tmp_path, _decisions_log(
        _spam_entry(ts), _spam_entry(ts), _spam_entry(ts)))

    result = daily_report.parse_decisions_24h(start, end)
    assert result["spam_moved"] == 3
    assert len(result["spam_entries"]) == 3

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Session 9B tests — written test-first.

Covers:
  - W10  decision-log field sanitization (newline / record-separator injection)
  - B9   prune_decisions_log + dashboard lifetime wiring
  - M15  deletion of cost-estimation code (spam_filter + learn_signals)
  - Retention: prune_pending_signals + daily-report report-total rollup

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_session9b.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
directory is never read or written. The module-level *_PATH constants are
monkeypatched to point at tmp copies (the suite's convention for redirecting
engine IO). file_lock is the REAL flock — never mocked.
"""
import json
import os
import subprocess
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
import spam_filter  # noqa: E402
import daily_report  # noqa: E402
import learn_signals  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _iso(days_ago: int) -> str:
    return (datetime.now() - timedelta(days=days_ago)).isoformat()


def _redirect_filter_memory(monkeypatch, tmp_path):
    """Point spam_filter's decision-log + lifetime-stats + pending paths at tmp."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    paths = {
        "DECISIONS_LOG_PATH": mem / "decisions.log",
        "LIFETIME_STATS_PATH": mem / "lifetime_stats.json",
        "PENDING_SIGNALS_PATH": mem / "pending_signals.json",
    }
    for attr, p in paths.items():
        monkeypatch.setattr(spam_filter, attr, p)
    return paths


# ===========================================================================
# W10 — decision-log field sanitization
# ===========================================================================

def test_sanitize_decision_log_field_newline_injection(monkeypatch, tmp_path):
    """A subject that injects a newline + a record separator must NOT be able to
    forge a second record. After writing one decision, splitting the log on the
    canonical '  ---\\n' separator must yield exactly one real record."""
    paths = _redirect_filter_memory(monkeypatch, tmp_path)

    # Subject crafted to (a) inject a newline and (b) inject a record separator.
    evil_subject = "hello\nINJECTED\n  ---\n[2099-01-01 00:00:00] ACCOUNT: forged"
    msg_data = {
        "message_id": "<evil@x>",
        "from_display_name": "Bad Guy",
        "from_email": "bad@x.com",
        "subject": evil_subject,
    }
    result = {"decision": "SPAM", "confidence": 0.99, "signals_hit": ["s1"]}

    spam_filter.log_decision("AcctA", msg_data, result, "MOVED to Junk")

    content = paths["DECISIONS_LOG_PATH"].read_text(encoding="utf-8")
    records = [r for r in content.split("  ---\n") if r.strip()]
    assert len(records) == 1, (
        f"newline/separator injection forged extra records: {records!r}")


# ===========================================================================
# B9 — prune_decisions_log
# ===========================================================================

def _decision_record(ts: str, decision: str = "NOT_SPAM") -> str:
    return (
        f"[{ts}] ACCOUNT: A\n"
        f"  MESSAGE-ID: <m>\n"
        f"  FROM: x <x@x.com>\n"
        f"  SUBJECT: s\n"
        f"  DECISION: {decision} (confidence: 0.10)\n"
        f"  SIGNALS HIT: \n"
        f"  ACTION: none\n"
        f"  ---\n"
    )


def test_prune_decisions_log_size_gate_skips(monkeypatch, tmp_path):
    """Below the 100 KB size floor, prune must NOT rewrite even with old records."""
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    old_ts = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")
    small = _decision_record(old_ts)
    paths["DECISIONS_LOG_PATH"].write_text(small, encoding="utf-8")

    spam_filter.prune_decisions_log(max_age_days=90)

    # Untouched (still contains the old record).
    assert paths["DECISIONS_LOG_PATH"].read_text(encoding="utf-8") == small
    # No lifetime rollup occurred.
    assert not paths["LIFETIME_STATS_PATH"].exists() or \
        spam_filter.load_lifetime_stats()["decisions_evaluated_lifetime"] == 0


def test_prune_decisions_log_drops_old_and_rolls_up(monkeypatch, tmp_path):
    """Above the size floor, records older than cutoff are dropped, survivors
    kept, and the dropped counts roll into lifetime_stats."""
    paths = _redirect_filter_memory(monkeypatch, tmp_path)

    old_ts = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")
    new_ts = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

    # Build a file over 100 KB: many old SPAM + old NOT_SPAM + a few fresh ones.
    n_old_spam = 400
    n_old_notspam = 400
    n_new = 5
    blob = (
        _decision_record(old_ts, "SPAM") * n_old_spam
        + _decision_record(old_ts, "NOT_SPAM") * n_old_notspam
        + _decision_record(new_ts, "SPAM") * n_new
    )
    paths["DECISIONS_LOG_PATH"].write_text(blob, encoding="utf-8")
    assert paths["DECISIONS_LOG_PATH"].stat().st_size >= 100 * 1024

    spam_filter.prune_decisions_log(max_age_days=90)

    content = paths["DECISIONS_LOG_PATH"].read_text(encoding="utf-8")
    survivors = [r for r in content.split("  ---\n") if r.strip()]
    assert len(survivors) == n_new, "only fresh records should survive"
    assert old_ts not in content, "old timestamps must be gone"

    stats = spam_filter.load_lifetime_stats()
    assert stats["decisions_evaluated_lifetime"] == n_old_spam + n_old_notspam
    assert stats["decisions_spam_lifetime"] == n_old_spam


def test_prune_decisions_log_unparseable_ts_kept(monkeypatch, tmp_path):
    """A record with no parseable timestamp must be KEPT (never dropped)."""
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    old_ts = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")
    garbage = "GARBAGE RECORD no timestamp here\n  ---\n"
    blob = _decision_record(old_ts, "SPAM") * 700 + garbage
    paths["DECISIONS_LOG_PATH"].write_text(blob, encoding="utf-8")
    assert paths["DECISIONS_LOG_PATH"].stat().st_size >= 100 * 1024

    spam_filter.prune_decisions_log(max_age_days=90)

    content = paths["DECISIONS_LOG_PATH"].read_text(encoding="utf-8")
    assert "GARBAGE RECORD" in content, "unparseable record must be kept"


# ===========================================================================
# B9 — dashboard wiring
# ===========================================================================

def _dash_env(monkeypatch, tmp_path):
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_paths, "DECISIONS_LOG", mem / "decisions.log")
    monkeypatch.setattr(app_paths, "LIFETIME_STATS_PATH", mem / "lifetime_stats.json")
    return mem


def test_dashboard_decision_counts_includes_lifetime(monkeypatch, tmp_path):
    mem = _dash_env(monkeypatch, tmp_path)
    new_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    (mem / "decisions.log").write_text(
        _decision_record(new_ts, "NOT_SPAM") * 3, encoding="utf-8")
    (mem / "lifetime_stats.json").write_text(json.dumps({
        "version": "1.0",
        "decisions_evaluated_lifetime": 100,
        "decisions_spam_lifetime": 40,
        "signals_submitted_lifetime": 0,
        "signals_approved_lifetime": 0,
        "signals_rejected_lifetime": 0,
    }), encoding="utf-8")

    today_n, week_n, life_n = dashboard._decision_counts()
    assert today_n == 3 and week_n == 3
    assert life_n == 3 + 100, "lifetime count must add the persistent counter"


def test_dashboard_spam_killed_includes_lifetime(monkeypatch, tmp_path):
    mem = _dash_env(monkeypatch, tmp_path)
    new_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    (mem / "decisions.log").write_text(
        _decision_record(new_ts, "SPAM") * 2, encoding="utf-8")
    (mem / "lifetime_stats.json").write_text(json.dumps({
        "version": "1.0",
        "decisions_evaluated_lifetime": 100,
        "decisions_spam_lifetime": 40,
        "signals_submitted_lifetime": 0,
        "signals_approved_lifetime": 0,
        "signals_rejected_lifetime": 0,
    }), encoding="utf-8")

    today_n, life_n = dashboard._spam_killed_counts()
    assert today_n == 2
    assert life_n == 2 + 40, "lifetime spam count must add the persistent counter"


def test_dashboard_load_lifetime_stats_missing_defaults(monkeypatch, tmp_path):
    _dash_env(monkeypatch, tmp_path)
    stats = dashboard._load_lifetime_stats()
    assert stats["decisions_evaluated_lifetime"] == 0
    assert stats["decisions_spam_lifetime"] == 0


# ===========================================================================
# M15 — cost-estimation deletion
# ===========================================================================

def test_m15_spam_filter_has_no_pricing_symbols():
    assert not hasattr(spam_filter, "MODEL_PRICING")
    assert not hasattr(spam_filter, "get_model_pricing")


def test_m15_record_token_usage_has_no_cost_key():
    usage = {
        "version": "1.0", "last_updated": "",
        "lifetime_input_tokens": 0, "lifetime_output_tokens": 0,
        "lifetime_api_calls": 0, "daily_records": [],
    }
    spam_filter.record_token_usage(usage, 100, 50, model="claude-haiku-4-5")
    rec = usage["daily_records"][0]
    assert "estimated_cost_usd" not in rec, "cost field must be gone from records"
    # Token tracking itself is preserved.
    assert rec["input_tokens"] == 100
    assert rec["output_tokens"] == 50
    assert rec["api_calls"] == 1


def test_m15_grep_finds_no_cost_symbols():
    """Belt-and-braces: grep both engine files for the deleted symbols."""
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sf = os.path.join(root, "payload", "MailWarden", "src", "spam_filter.py")
    ls = os.path.join(root, "payload", "MailWarden", "src", "learn_signals.py")
    proc = subprocess.run(
        ["grep", "-E", "MODEL_PRICING|get_model_pricing|estimated_cost_usd", sf, ls],
        capture_output=True, text=True,
    )
    assert proc.returncode == 1, (
        f"grep found deleted cost symbols:\n{proc.stdout}")
    assert proc.stdout.strip() == ""


# ===========================================================================
# Retention — prune_pending_signals
# ===========================================================================

def _pending(*convs) -> dict:
    return {"version": "1.0", "conversations": list(convs)}


def test_prune_pending_keeps_awaiting_reply_regardless_of_age(monkeypatch, tmp_path):
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    conv = {"id": "C1", "status": "awaiting_reply", "created": _iso(500)}
    paths["PENDING_SIGNALS_PATH"].write_text(json.dumps(_pending(conv)))

    spam_filter.prune_pending_signals(max_age_days=90)

    data = json.loads(paths["PENDING_SIGNALS_PATH"].read_text())
    ids = [c["id"] for c in data["conversations"]]
    assert "C1" in ids, "awaiting_reply must never be pruned"


def test_prune_pending_keeps_recent_resolved(monkeypatch, tmp_path):
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    conv = {"id": "C2", "status": "expired", "resolution": "approved",
            "created": _iso(1)}
    paths["PENDING_SIGNALS_PATH"].write_text(json.dumps(_pending(conv)))

    spam_filter.prune_pending_signals(max_age_days=90)

    data = json.loads(paths["PENDING_SIGNALS_PATH"].read_text())
    ids = [c["id"] for c in data["conversations"]]
    assert "C2" in ids, "recently created resolved convs must be kept"


def test_prune_pending_drops_old_resolved_and_rolls_up(monkeypatch, tmp_path):
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    convs = [
        {"id": "A", "status": "resolved", "resolution": "approved",
         "created": _iso(200)},
        {"id": "B", "status": "resolved", "resolution": "rejected",
         "created": _iso(150)},
        {"id": "C", "status": "expired", "resolution": "expired",
         "created": _iso(120)},
        {"id": "KEEP", "status": "awaiting_reply", "created": _iso(300)},
    ]
    paths["PENDING_SIGNALS_PATH"].write_text(json.dumps(_pending(*convs)))

    spam_filter.prune_pending_signals(max_age_days=90)

    data = json.loads(paths["PENDING_SIGNALS_PATH"].read_text())
    ids = sorted(c["id"] for c in data["conversations"])
    assert ids == ["KEEP"], "only the awaiting_reply conv should survive"

    stats = spam_filter.load_lifetime_stats()
    assert stats["signals_submitted_lifetime"] == 3
    assert stats["signals_approved_lifetime"] == 1
    assert stats["signals_rejected_lifetime"] == 1


def test_prune_pending_missing_created_kept(monkeypatch, tmp_path):
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    conv = {"id": "NOCREATED", "status": "resolved", "resolution": "approved"}
    paths["PENDING_SIGNALS_PATH"].write_text(json.dumps(_pending(conv)))

    spam_filter.prune_pending_signals(max_age_days=90)

    data = json.loads(paths["PENDING_SIGNALS_PATH"].read_text())
    ids = [c["id"] for c in data["conversations"]]
    assert "NOCREATED" in ids, "missing/unparseable created must be kept"


def test_prune_pending_no_drop_no_write(monkeypatch, tmp_path):
    """If nothing is dropped, the file is not rewritten (no spurious churn)."""
    paths = _redirect_filter_memory(monkeypatch, tmp_path)
    conv = {"id": "FRESH", "status": "resolved", "resolution": "approved",
            "created": _iso(1)}
    original = json.dumps(_pending(conv))
    paths["PENDING_SIGNALS_PATH"].write_text(original)
    mtime_before = paths["PENDING_SIGNALS_PATH"].stat().st_mtime_ns

    spam_filter.prune_pending_signals(max_age_days=90)

    assert paths["PENDING_SIGNALS_PATH"].stat().st_mtime_ns == mtime_before


# ===========================================================================
# Retention — daily-report total includes lifetime counters
# ===========================================================================

def test_daily_report_total_adds_lifetime_counter(monkeypatch, tmp_path):
    """expire_pending_signals report totals = retained count + lifetime counter."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    pend = mem / "pending_signals.json"
    life = mem / "lifetime_stats.json"
    monkeypatch.setattr(daily_report, "PENDING_SIGNALS_PATH", pend)
    monkeypatch.setattr(daily_report, "LIFETIME_STATS_PATH", life)

    # Two retained resolved conversations (1 approved, 1 rejected) + 1 awaiting.
    convs = [
        {"id": "R1", "status": "resolved", "resolution": "approved",
         "created": _iso(1), "expires": _iso(-30)},
        {"id": "R2", "status": "resolved", "resolution": "rejected",
         "created": _iso(1), "expires": _iso(-30)},
        {"id": "P1", "status": "awaiting_reply", "created": _iso(1),
         "expires": _iso(-30)},
    ]
    pend.write_text(json.dumps({"version": "1.0", "conversations": convs}))
    life.write_text(json.dumps({
        "version": "1.0",
        "decisions_evaluated_lifetime": 0,
        "decisions_spam_lifetime": 0,
        "signals_submitted_lifetime": 10,
        "signals_approved_lifetime": 4,
        "signals_rejected_lifetime": 3,
    }))

    import logging
    result = daily_report.expire_pending_signals(logging.getLogger("t"))

    # retained: 3 convs (submitted), 1 approved, 1 rejected
    assert result["total_submitted"] == 3 + 10
    assert result["total_approved"] == 1 + 4
    assert result["total_rejected"] == 1 + 3


# ===========================================================================
# Retention — run_filter must load `pending` AFTER pruning (source-order guard)
# ===========================================================================

def test_run_filter_loads_pending_after_prune_source_order():
    """Structural guard (audit Session 9B fix): run_filter must build its
    in-memory `pending` snapshot AFTER prune_pending_signals() rewrites the
    file on disk. If `pending` is loaded BEFORE the prune, the stale snapshot
    still holds the conversations the prune dropped, and the first
    persist_pending_merge() of the run re-appends them to disk — resurrecting
    pruned conversations AND double-counting them against lifetime_stats.

    A full run_filter integration test needs live IMAP, so we assert the
    source ordering rather than build a fragile mega-mock (cf.
    test_locking_engine.py::test_t5b_persist_progress_is_called_per_account_in_source)."""
    import inspect
    src = inspect.getsource(spam_filter.run_filter)
    prune_idx = src.index("prune_pending_signals()")
    load_idx = src.index("pending = load_pending_signals()")
    assert prune_idx < load_idx, (
        "pending must be loaded AFTER prune_pending_signals() so the prune is "
        "not undone by a stale in-memory snapshot via persist_pending_merge"
    )

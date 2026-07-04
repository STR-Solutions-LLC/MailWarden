#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Integration-audit finding #12 — the dry-run classified-message sidecar.

Before this fix, a Dry Run SPAM verdict was deliberately NOT recorded in
processed_ids (so the first real run could still action it) — but nothing
else remembered it either. The message stayed UNSEEN and uncached, so every
tick re-fetched and RE-CLASSIFIED it (1-2 paid API calls per tick, forever),
appended another DECISION: SPAM record to decisions.log (duplicate daily-
report entries, each with its own APPROVE token), and permanently inflated
the sender-history junked tally.

The fix: memory/dry_run_verdicts.json, a sidecar ledger mirroring
processed_ids (same shape, same atomic write, same 30-day prune-on-load),
consulted ONLY while dry_run is True, immediately before the paid classifier
call. Recorded there: exactly the messages the cache_this gate leaves out of
processed_ids (dry-run "spam" decisions, including a below-threshold SPAM
decision that was delivered). Transition semantics: the first real run never
reads the sidecar, so each sidecar'd message gets ONE fresh classification
and a real action.

Harness style mirrors tests/test_finalize_seen_timing.py's _run_harness — a
full spam_filter.run_filter(force=True) drive with every IO/network call
mocked, run twice ("two ticks") against shared in-memory stores.

Run with the test venv:
  tests/.venv/bin/python -m pytest tests/test_dry_run_verdict_cache.py -q
"""
import json
import logging as _logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_dry_run_verdict_cache")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


def _spam_msg(msg_id="<spam-1@evil.example>"):
    """An ordinary external message: no subject command, no SFID/MWR reply,
    not whitelisted/blacklisted — it flows all the way to the classifier."""
    return {
        "message_id": msg_id, "from_email": "spammer@evil.example",
        "from_display_name": "Totally Real Pharmacy",
        "subject": "Cheap meds today only",
        "plain_text_body": "buy now", "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }


def _make_env(tmp_path, monkeypatch, *, dry_run=True,
              classify_result=None, real_sidecar_io=False):
    """Baseline mocks for a run_filter drive. Returns a mutable env dict:
    cfg can be flipped between ticks (dry_run on/off); `processed` and
    `sidecar` are SHARED store objects returned by the load_* mocks on every
    tick, so state persists across run_filter calls exactly as the real
    files would. decisions.log is REAL file IO under tmp_path (real
    log_decision/append_decision, real file_lock)."""
    env = {
        "classify_calls": 0,
        "classify_result": classify_result or {
            "decision": "SPAM", "confidence": 0.99, "signals_hit": ["s1"]},
        "spam_actions": [],
        "processed": {"version": "1.0", "last_updated": "", "ids": {}},
        "sidecar": {"version": "1.0", "last_updated": "", "ids": {}},
        "sidecar_flushes": 0,
        "send_email": [],
    }
    cfg = {
        "filter": {"dry_run": dry_run, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": _ACCOUNT_KEY,
                 "from_address": _ACCOUNT_KEY},
        "summary": {"recipient_address": _ACCOUNT_KEY},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{"name": "Acct", "enabled": True,
                      "username": _ACCOUNT_KEY,
                      "imap_host": "imap.example.com", "junk_folder": "Junk",
                      "folders_to_scan": ["INBOX"]}],
    }
    env["cfg"] = cfg

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids",
                        lambda: env["processed"])
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: {"domains": [], "addresses": [],
                                        "_addresses_set": set(),
                                        "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "load_blacklist",
                        lambda logger: {"addresses": [], "domains": [],
                                        "display_names": [],
                                        "subject_keywords": []})
    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": [], "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "detect_conflicts",
                        lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage", lambda: {})
    monkeypatch.setattr(spam_filter, "new_token_delta", lambda: {})
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: {"conversations": []})
    monkeypatch.setattr(spam_filter, "persist_progress",
                        lambda processed, tu, td: None)
    monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                        lambda signals, username=None,
                        approvals_active=False: "PROMPT")
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "prune_decisions_log", lambda: None)
    monkeypatch.setattr(spam_filter, "prune_pending_signals", lambda: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "scan_train_folder",
                        lambda conn, account, config, logger: None)
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed",
                        lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: {})
    monkeypatch.setattr(spam_filter, "load_rule_reviews_store",
                        lambda logger: {})
    monkeypatch.setattr(spam_filter, "persist_pending_merge",
                        lambda pending, touched_ids=(), **k: None)
    monkeypatch.setattr(spam_filter, "mark_uid_seen",
                        lambda conn, uid, logger: None)

    def _send(config, subject, body, logger, to_addr=None):
        env["send_email"].append((subject, body, to_addr))
    monkeypatch.setattr(spam_filter, "send_email", _send)

    # Deterministic no-verdict pre-classifier: the message must reach the
    # PAID classifier boundary (that is the surface under test), and no
    # DNSBL/network lookups may run.
    monkeypatch.setattr(
        spam_filter, "check_header_signals",
        lambda headers, body, sending_ip=None, dnsbl_timeout=3.0: {
            "pre_classifier_verdict": "NONE",
            "pre_classifier_confidence": 0.0,
            "hard_signals": [], "soft_signals": []})

    def _classify(*a, **k):
        env["classify_calls"] += 1
        return dict(env["classify_result"]), None
    monkeypatch.setattr(spam_filter, "classify_email", _classify)

    def _action(conn, uid, account, logger):
        env["spam_actions"].append(uid)
        return "MOVED to Junk"
    monkeypatch.setattr(spam_filter, "execute_spam_action", _action)

    # Sidecar store: shared dict across ticks (unless a test exercises the
    # REAL loader/saver against tmp files).
    if not real_sidecar_io:
        monkeypatch.setattr(spam_filter, "load_dry_run_verdicts",
                            lambda: env["sidecar"])

        def _flush_sidecar(dry_verdicts):
            env["sidecar_flushes"] += 1
            assert dry_verdicts is env["sidecar"]
        monkeypatch.setattr(spam_filter, "persist_dry_run_verdicts",
                            _flush_sidecar)
    else:
        monkeypatch.setattr(spam_filter, "DRY_RUN_VERDICTS_PATH",
                            tmp_path / "dry_run_verdicts.json")

    # Real decisions.log under tmp (real append_decision + real file_lock).
    monkeypatch.setattr(spam_filter, "DECISIONS_LOG_PATH",
                        tmp_path / "decisions.log")

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: [b"1"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"raw")
    return env


def _set_message(monkeypatch, msg_data):
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_data))


def _processed_ids(env):
    return [e[0] for e in env["processed"].get("ids", {}).get(_ACCOUNT_KEY, [])]


def _sidecar_ids(env):
    return [e[0] for e in env["sidecar"].get("ids", {}).get(_ACCOUNT_KEY, [])]


def _decision_records(tmp_path, needle):
    log = tmp_path / "decisions.log"
    if not log.exists():
        return 0
    recs = [r for r in log.read_text().split("  ---\n") if r.strip()]
    return sum(1 for r in recs if needle in r)


# ═════════════════════════════════════════════════════════════════════════
# 1. Dry-run SPAM is billed exactly once across two ticks
# ═════════════════════════════════════════════════════════════════════════

def test_dry_run_spam_billed_once_across_two_ticks(tmp_path, monkeypatch):
    msg = _spam_msg()
    env = _make_env(tmp_path, monkeypatch, dry_run=True)
    _set_message(monkeypatch, msg)

    spam_filter.run_filter(force=True)   # tick 1: classify + log + sidecar
    spam_filter.run_filter(force=True)   # tick 2: sidecar hit, NO API call

    assert env["classify_calls"] == 1, "dry-run SPAM must be billed ONCE"
    assert env["spam_actions"] == [], "dry run must never move mail"
    assert msg["message_id"] not in _processed_ids(env), (
        "dry-run SPAM must stay OUT of processed_ids (first real run still "
        "actions it)")
    assert _sidecar_ids(env).count(msg["message_id"]) == 1
    assert _decision_records(tmp_path, "DECISION: SPAM") == 1, (
        "exactly one decisions.log record — no duplicate report entries")
    assert env["sidecar_flushes"] > 0, "dry run must flush the sidecar"


# ═════════════════════════════════════════════════════════════════════════
# 2. Below-threshold SPAM decision (delivered) is also billed exactly once
# ═════════════════════════════════════════════════════════════════════════

def test_below_threshold_spam_decision_billed_once(tmp_path, monkeypatch):
    """decision == "SPAM" but confidence < threshold: the message is
    DELIVERED ("No action taken") yet the cache_this gate still keys off the
    raw decision, so it too was left uncached and re-billed every tick. The
    sidecar keys off `not cache_this`, covering this sub-case."""
    msg = _spam_msg("<lowconf-1@evil.example>")
    env = _make_env(tmp_path, monkeypatch, dry_run=True,
                    classify_result={"decision": "SPAM", "confidence": 0.10,
                                     "signals_hit": []})
    _set_message(monkeypatch, msg)

    spam_filter.run_filter(force=True)
    spam_filter.run_filter(force=True)

    assert env["classify_calls"] == 1
    assert msg["message_id"] not in _processed_ids(env)
    assert _sidecar_ids(env).count(msg["message_id"]) == 1


# ═════════════════════════════════════════════════════════════════════════
# 3. Dry-run -> real transition: one fresh classification, one real action
# ═════════════════════════════════════════════════════════════════════════

def test_dry_run_to_real_transition_actions_once(tmp_path, monkeypatch):
    """Chosen transition semantics (approved): the sidecar is consulted ONLY
    while dry_run is True. The first real run re-classifies the message
    fresh (exactly one more API call — current rules are honored) and
    actions it. The sidecar entry must NOT block the real run: the gate is
    dry_run-only, proven here by behavior."""
    msg = _spam_msg("<transition-1@evil.example>")
    env = _make_env(tmp_path, monkeypatch, dry_run=True)
    _set_message(monkeypatch, msg)

    spam_filter.run_filter(force=True)               # dry tick
    assert env["classify_calls"] == 1
    assert msg["message_id"] in _sidecar_ids(env)
    flushes_after_dry = env["sidecar_flushes"]

    env["cfg"]["filter"]["dry_run"] = False          # owner turns Dry Run off
    spam_filter.run_filter(force=True)               # first REAL run

    assert env["classify_calls"] == 2, (
        "transition = exactly ONE fresh classification (sidecar entry must "
        "not block the real run, and no third call may happen)")
    assert len(env["spam_actions"]) == 1, "the message must be actioned once"
    assert msg["message_id"] in _processed_ids(env), (
        "real run records it processed — never touched again")
    assert env["sidecar_flushes"] == flushes_after_dry, (
        "a real run must never write the sidecar")

    # And a THIRD run (still real) is a pure processed_ids skip.
    spam_filter.run_filter(force=True)
    assert env["classify_calls"] == 2
    assert len(env["spam_actions"]) == 1


# ═════════════════════════════════════════════════════════════════════════
# 4. NOT-SPAM dry-run behavior is unchanged
# ═════════════════════════════════════════════════════════════════════════

def test_not_spam_dry_run_unchanged(tmp_path, monkeypatch):
    msg = _spam_msg("<ham-1@friendly.example>")
    env = _make_env(tmp_path, monkeypatch, dry_run=True,
                    classify_result={"decision": "NOT_SPAM",
                                     "confidence": 0.05, "signals_hit": []})
    _set_message(monkeypatch, msg)

    spam_filter.run_filter(force=True)
    spam_filter.run_filter(force=True)

    assert env["classify_calls"] == 1
    assert msg["message_id"] in _processed_ids(env), (
        "dry-run NOT-SPAM still goes to processed_ids, exactly as before")
    assert msg["message_id"] not in _sidecar_ids(env), (
        "the sidecar is only for the decisions left out of processed_ids")
    assert _decision_records(tmp_path, "DECISION: NOT_SPAM") == 1


# ═════════════════════════════════════════════════════════════════════════
# 5. Sidecar file resilience: missing / malformed / real end-to-end IO
# ═════════════════════════════════════════════════════════════════════════

def test_sidecar_missing_file_yields_default(tmp_path, monkeypatch):
    monkeypatch.setattr(spam_filter, "DRY_RUN_VERDICTS_PATH",
                        tmp_path / "nope" / "dry_run_verdicts.json")
    data = spam_filter.load_dry_run_verdicts()
    assert data == {"version": "1.0", "last_updated": "", "ids": {}}


def test_sidecar_malformed_json_yields_default(tmp_path, monkeypatch):
    p = tmp_path / "dry_run_verdicts.json"
    p.write_text("{ broken json", encoding="utf-8")
    monkeypatch.setattr(spam_filter, "DRY_RUN_VERDICTS_PATH", p)
    data = spam_filter.load_dry_run_verdicts()
    assert data == {"version": "1.0", "last_updated": "", "ids": {}}


def test_sidecar_real_io_end_to_end(tmp_path, monkeypatch):
    """Full run_filter drive with the REAL loader/saver (real file_lock,
    real mkstemp+os.replace) against tmp files: two dry ticks — separate
    load-from-disk each time — still bill exactly once, and the sidecar
    file on disk is valid JSON carrying the msg id."""
    msg = _spam_msg("<realio-1@evil.example>")
    env = _make_env(tmp_path, monkeypatch, dry_run=True, real_sidecar_io=True)
    _set_message(monkeypatch, msg)

    spam_filter.run_filter(force=True)
    spam_filter.run_filter(force=True)

    assert env["classify_calls"] == 1
    on_disk = json.loads((tmp_path / "dry_run_verdicts.json").read_text())
    ids = [e[0] for e in on_disk["ids"][_ACCOUNT_KEY]]
    assert ids.count(msg["message_id"]) == 1
    assert on_disk["last_updated"]


# ═════════════════════════════════════════════════════════════════════════
# 6. Sidecar 30-day prune-on-load (parity with processed_ids)
# ═════════════════════════════════════════════════════════════════════════

def test_sidecar_prunes_entries_older_than_30_days(tmp_path, monkeypatch):
    stale = (datetime.now() - timedelta(days=31)).isoformat()
    fresh = datetime.now().isoformat()
    p = tmp_path / "dry_run_verdicts.json"
    p.write_text(json.dumps({
        "version": "1.0", "last_updated": fresh,
        "ids": {_ACCOUNT_KEY: [["<old@x>", stale], ["<new@x>", fresh]]},
    }), encoding="utf-8")
    monkeypatch.setattr(spam_filter, "DRY_RUN_VERDICTS_PATH", p)

    data = spam_filter.load_dry_run_verdicts()
    ids = [e[0] for e in data["ids"][_ACCOUNT_KEY]]
    assert ids == ["<new@x>"], "31-day-old entry must be pruned on load"


def test_sidecar_legacy_string_list_migrates(tmp_path, monkeypatch):
    """Same legacy-format migration contract as load_processed_ids."""
    p = tmp_path / "dry_run_verdicts.json"
    p.write_text(json.dumps({
        "version": "1.0", "last_updated": "",
        "ids": {_ACCOUNT_KEY: ["<plain@x>"]},
    }), encoding="utf-8")
    monkeypatch.setattr(spam_filter, "DRY_RUN_VERDICTS_PATH", p)

    data = spam_filter.load_dry_run_verdicts()
    entries = data["ids"][_ACCOUNT_KEY]
    assert entries[0][0] == "<plain@x>" and len(entries[0]) == 2

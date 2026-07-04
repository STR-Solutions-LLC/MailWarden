#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Integration-audit finding #4 — SFID/MWR reply handlers must not mark a
message \\Seen until the handler has actually completed.

Before this fix, both the `if sfid_match:` branch and the `if mwr_match:`
branch (APPROVE and KEEP/DROP sub-cases) called mark_uid_seen(conn, uid,
logger) once, near the top, immediately after detecting the reply — BEFORE
any of the real processing (conversation lookup, expiry check, persisting
state, applying the refinement/blocklist entry, sending the confirmation)
ran. If any of that later code raised, the account-level `except Exception`
in run_filter (which only logs and moves on) swallowed it — but the message
was already \\Seen. Since the IMAP fetch only searches UNSEEN messages, a
\\Seen-but-unrecorded message is never refetched: the owner's YES/NO/
APPROVE/KEEP/DROP reply is silently and permanently lost.

The fix (mirroring the existing W4 `_finalize_command` discipline used by
the subject-line command handlers) removes the up-front mark and instead
calls the same `_finalize_command()` closure at each branch's genuine
success exit, right before its `continue`. These tests assert the crash
contract directly: a mid-handler exception must leave the message UNSEEN
and unrecorded (retryable next tick), while the happy path must still
finalize exactly once (no regression).

Harness style mirrors tests/test_rule_review.py's `_rr_harness` /
tests/test_cascade.py's `_run_filter_cascade_harness` — a full
spam_filter.run_filter(force=True) drive with every IO/network call mocked.
"""
import logging as _logging
import os
import sys
from datetime import datetime, timedelta

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_finalize_seen_timing")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


def _base_msg(subject, body, from_email=_ACCOUNT_KEY,
              msg_id="<reply-1@example.com>"):
    return {
        "message_id": msg_id, "from_email": from_email,
        "from_display_name": "Owner", "subject": subject,
        "plain_text_body": body, "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }


def _run_harness(monkeypatch, *, msg_data, pending=None,
                  approvals_store=None, patches=None):
    """Drive spam_filter.run_filter(force=True) with one UNSEEN message and
    every IO/network call mocked. `patches` is a dict of
    {spam_filter attribute name: replacement callable} applied on top of the
    baseline mocks (used to inject a crash into one specific helper).
    Returns {"mark_uid_seen": <call count>, "processed": <final processed
    dict captured from persist_progress>, "send_email": [(subject, body,
    to_addr), ...]}."""
    calls = {"mark_uid_seen": 0, "processed": None, "send_email": []}

    cfg = {
        "filter": {"dry_run": False, "confidence_threshold": 0.85,
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

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
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
                        lambda: pending if pending is not None
                        else {"conversations": []})

    def _persist(processed, tu, td):
        calls["processed"] = processed
    monkeypatch.setattr(spam_filter, "persist_progress", _persist)

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
    monkeypatch.setattr(spam_filter, "log_decision", lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "_command_sender_is_owner",
                        lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "_command_auth_ok",
                        lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "_notify_unverified_command",
                        lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: dict(approvals_store or {}))
    monkeypatch.setattr(spam_filter, "load_rule_reviews_store",
                        lambda logger: {})
    monkeypatch.setattr(spam_filter, "append_refinement_log",
                        lambda event: None)
    monkeypatch.setattr(spam_filter, "persist_pending_merge",
                        lambda pending, touched_ids=(), **k: None)
    monkeypatch.setattr(spam_filter, "add_blocklist_entry_local",
                        lambda value, kind, scope, logger: True)
    monkeypatch.setattr(spam_filter, "add_approved_domain",
                        lambda domain, logger: True)
    monkeypatch.setattr(spam_filter, "retire_ai_refinement",
                        lambda rid, logger: True)
    monkeypatch.setattr(spam_filter, "dequeue_rule_review",
                        lambda rid, logger: True)
    monkeypatch.setattr(spam_filter, "enqueue_rule_reviews",
                        lambda pairs, signals, logger: [])

    def _send(config, subject, body, logger, to_addr=None):
        calls["send_email"].append((subject, body, to_addr))
    monkeypatch.setattr(spam_filter, "send_email", _send)

    def _seen(conn, uid, logger):
        calls["mark_uid_seen"] += 1
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    monkeypatch.setattr(spam_filter, "classify_email",
                        lambda *a, **k: ({"decision": "NOT_SPAM",
                                          "confidence": 0.0,
                                          "signals_hit": []}, None))
    monkeypatch.setattr(spam_filter, "execute_spam_action",
                        lambda *a, **k: "moved")

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: [b"1"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"raw")
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_data))

    for name, fn in (patches or {}).items():
        monkeypatch.setattr(spam_filter, name, fn)

    spam_filter.run_filter(force=True)
    return calls


def _msg_ids_recorded(calls):
    ids = (calls["processed"] or {}).get("ids", {}).get(_ACCOUNT_KEY, [])
    return [e[0] for e in ids]


def _block_sender_conv(expires_days=1):
    """A pending block_sender_proposal awaiting the owner's YES/NO — the
    simplest SFID conv_kind to drive the affirmative path end to end."""
    return {
        "conversations": [{
            "id": "SFID-TEST1",
            "status": "awaiting_reply",
            "kind": "block_sender_proposal",
            "blocklist_entry": {"value": "spam.example", "kind": "domain",
                                 "scope": "all"},
            "conversation_history": [],
            "expires": (datetime.now()
                        + timedelta(days=expires_days)).isoformat(),
        }],
    }


# ═════════════════════════════════════════════════════════════════════════
# SFID reply branch
# ═════════════════════════════════════════════════════════════════════════

def test_sfid_reply_crash_leaves_message_retryable(monkeypatch):
    """A mid-handler exception (persist_pending_merge raising, e.g. a
    signals.json I/O error) must leave the reply UNSEEN and unrecorded so
    the next tick retries it, instead of losing the owner's YES forever."""
    def _boom(pending, touched_ids=(), **k):
        raise RuntimeError("disk full")
    msg = _base_msg("Re: [SFID-TEST1] Block sender?", "YES")
    calls = _run_harness(
        monkeypatch, msg_data=msg, pending=_block_sender_conv(),
        patches={"persist_pending_merge": _boom})
    assert calls["mark_uid_seen"] == 0, (
        "crash must NOT mark the message Seen")
    assert msg["message_id"] not in _msg_ids_recorded(calls), (
        "crash must NOT record the message processed")


def test_sfid_reply_happy_path_finalizes_once(monkeypatch):
    """Clean YES on a block_sender_proposal: finalize (mark Seen + record
    processed) must happen exactly once — no regression from the fix."""
    msg = _base_msg("Re: [SFID-TEST1] Block sender?", "YES")
    calls = _run_harness(monkeypatch, msg_data=msg,
                        pending=_block_sender_conv())
    assert calls["mark_uid_seen"] == 1
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "Sender blocked" in subject


def test_sfid_own_email_still_record_only_not_seen(monkeypatch):
    """Regression guard: MailWarden's own outgoing SFID email (empty reply
    after stripping quotes) must remain record-only / left UNSEEN (finding
    #13) — the fix must not route this exit through _finalize_command()."""
    msg = _base_msg("Re: [SFID-TEST1] Block sender?", "> quoted only\n")
    calls = _run_harness(monkeypatch, msg_data=msg,
                        pending=_block_sender_conv())
    assert calls["mark_uid_seen"] == 0, (
        "own/empty SFID email must NOT be marked Seen")
    assert msg["message_id"] in _msg_ids_recorded(calls), (
        "own/empty SFID email must still be recorded processed"
        " (loop prevention)")


# ═════════════════════════════════════════════════════════════════════════
# MWR reply branch — APPROVE sub-case
# ═════════════════════════════════════════════════════════════════════════

def _approve_store(token="tok1"):
    return {token: {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": {"1": {"from_domain": "give.example",
                          "from": "News <n@give.example>",
                          "subject": "s"}},
        "rule_reviews": {},
    }}


def test_mwr_approve_crash_leaves_message_retryable(monkeypatch):
    """A mid-handler exception (add_approved_domain raising, e.g. memory/
    missing) must leave the APPROVE reply UNSEEN and unrecorded."""
    def _boom(domain, logger):
        raise RuntimeError("memory/ missing")
    msg = _base_msg("Re: MailWarden Report — July 03 [MWR-tok1]",
                    "APPROVE 1")
    calls = _run_harness(
        monkeypatch, msg_data=msg, approvals_store=_approve_store(),
        patches={"add_approved_domain": _boom})
    assert calls["mark_uid_seen"] == 0
    assert msg["message_id"] not in _msg_ids_recorded(calls)


def test_mwr_approve_happy_path_finalizes_once(monkeypatch):
    """Clean APPROVE 1: finalize exactly once — no regression."""
    msg = _base_msg("Re: MailWarden Report — July 03 [MWR-tok1]",
                    "APPROVE 1")
    calls = _run_harness(monkeypatch, msg_data=msg,
                        approvals_store=_approve_store())
    assert calls["mark_uid_seen"] == 1
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1
    assert len(calls["send_email"]) == 1


# ═════════════════════════════════════════════════════════════════════════
# MWR reply branch — KEEP/DROP sub-case
# ═════════════════════════════════════════════════════════════════════════

def _review_store(token="tok1"):
    return {token: {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": {},
        "rule_reviews": {"1": "R-20260703-aaaa"},
    }}


def test_mwr_keepdrop_crash_leaves_message_retryable(monkeypatch):
    """A mid-handler exception (retire_ai_refinement raising) must leave the
    DROP reply UNSEEN and unrecorded."""
    def _boom(rid, logger):
        raise RuntimeError("signals.json locked")
    msg = _base_msg("Re: MailWarden Report — July 03 [MWR-tok1]", "DROP 1")
    calls = _run_harness(
        monkeypatch, msg_data=msg, approvals_store=_review_store(),
        patches={"retire_ai_refinement": _boom})
    assert calls["mark_uid_seen"] == 0
    assert msg["message_id"] not in _msg_ids_recorded(calls)


def test_mwr_keepdrop_happy_path_finalizes_once(monkeypatch):
    """Clean DROP 1: finalize exactly once — no regression."""
    msg = _base_msg("Re: MailWarden Report — July 03 [MWR-tok1]", "DROP 1")
    calls = _run_harness(monkeypatch, msg_data=msg,
                        approvals_store=_review_store())
    assert calls["mark_uid_seen"] == 1
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1
    assert len(calls["send_email"]) == 1

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""C5b — per-run junk-action cap.

run_filter counts successful, non-dry-run spam actions and stops before
classifying any further message once max_junk_actions_per_run is reached, so a
misfiring rule or a flood can never junk an unbounded number of messages in one
tick. Remaining messages are left UNSEEN and UNCLASSIFIED (no API spend).

Harness mirrors tests/test_batch5_fetch_loop.py._run (full run_filter drive,
every IO/network call mocked), specialized to force a SPAM verdict and spy on
execute_spam_action.
"""
import logging as _logging
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_junk_action_cap")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


def _msg(msg_id):
    return {
        "message_id": msg_id, "from_email": "stranger@somewhere.example",
        "from_display_name": "Someone", "subject": "Buy now",
        "plain_text_body": "spammy words", "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "received_headers": [], "received_headers_first_3": [],
        "from_header_raw": "Someone <stranger@somewhere.example>",
        "_mime_msg": None,
    }


def _run(monkeypatch, *, n_uids, cap, dry_run=False, action_result="moved"):
    """Drive run_filter over n_uids spam messages with the junk cap set to
    `cap`. Returns {"execute": <#execute_spam_action calls>,
    "classified": [message_id,...]}."""
    spies = {"execute": 0, "classified": []}

    cfg = {
        "filter": {"dry_run": dry_run, "confidence_threshold": 0.85,
                   "max_emails_per_run": 1000, "max_junk_actions_per_run": cap,
                   "log_level": "INFO"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": _ACCOUNT_KEY,
                 "from_address": _ACCOUNT_KEY},
        "summary": {"recipient_address": _ACCOUNT_KEY},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{"name": "Acct", "enabled": True, "username": _ACCOUNT_KEY,
                      "imap_host": "imap.example.com", "junk_folder": "Junk",
                      "folders_to_scan": ["INBOX"]}],
    }
    uids = {str(i).encode(): _msg(f"<m-{i}@ex.com>") for i in range(n_uids)}

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_dry_run_verdicts", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "persist_dry_run_verdicts", lambda dv: None)
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: {"domains": [], "addresses": [],
                                        "_addresses_set": set(),
                                        "_addresses_approve_set": set(),
                                        "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "load_blacklist",
                        lambda logger: {"addresses": [], "domains": [],
                                        "display_names": [], "subject_keywords": []})
    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": [], "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "detect_conflicts", lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage", lambda: {})
    monkeypatch.setattr(spam_filter, "new_token_delta", lambda: {})
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: {"conversations": []})
    monkeypatch.setattr(spam_filter, "persist_progress", lambda p, tu, td: None)
    monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                        lambda signals, username=None, approvals_active=False,
                        whitelist_curate_active=False: "PROMPT")
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "prune_decisions_log", lambda: None)
    monkeypatch.setattr(spam_filter, "prune_pending_signals", lambda: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "scan_train_folder",
                        lambda conn, account, config, logger: None)
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed", lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "log_decision", lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "record_pre_classifier_skip", lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "send_email", lambda *a, **k: None)

    def _seen(conn, uid, logger):
        pass
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    def _classify(client, system_prompt, msg_data, *a, **k):
        spies["classified"].append(msg_data.get("message_id"))
        return ({"decision": "SPAM", "confidence": 1.0, "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify)

    def _execute(conn, uid, account, logger):
        spies["execute"] += 1
        return action_result
    monkeypatch.setattr(spam_filter, "execute_spam_action", _execute)

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: list(uids))
    monkeypatch.setattr(spam_filter, "fetch_message_id",
                        lambda conn, uid, logger: uids[uid]["message_id"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"RAW:" + uid)
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(uids[raw.split(b":", 1)[1]]))

    spam_filter.run_filter(force=True)
    return spies


def test_cap_stops_after_exactly_n_actions(monkeypatch):
    spies = _run(monkeypatch, n_uids=60, cap=25)
    assert spies["execute"] == 25, "must take exactly the capped number of actions"
    # The 26th message never reaches classification (break is at the loop top).
    assert len(spies["classified"]) == 25


def test_dry_run_never_counts_toward_cap(monkeypatch):
    # In Dry Run execute_spam_action is never called, so the cap can't trip:
    # every message is still classified.
    spies = _run(monkeypatch, n_uids=60, cap=25, dry_run=True)
    assert spies["execute"] == 0
    assert len(spies["classified"]) == 60


def test_failed_action_does_not_increment_cap(monkeypatch):
    # A FAILED action is not a successful junking, so it must not count toward
    # the cap — all 60 are attempted.
    spies = _run(monkeypatch, n_uids=60, cap=25, action_result="[MOVE FAILED to Junk]")
    assert spies["execute"] == 60
    assert len(spies["classified"]) == 60

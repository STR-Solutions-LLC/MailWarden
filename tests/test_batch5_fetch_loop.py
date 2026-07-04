#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Integration-audit Batch 5, finding #20 — header-first fetch in run_filter.

Bandwidth/cost only (no correctness change): the INBOX loop used to fully
download every UNSEEN body every tick even when the message's Message-ID was
already handled. run_filter now PEEK-fetches ONLY the Message-ID header first
and, when that ID is already in EITHER processed set, skips the full-body
download entirely:

    peek_msg_id = fetch_message_id(conn, uid, logger)
    if peek_msg_id and (peek_msg_id in account_processed
                        or peek_msg_id in account_dry_seen):
        continue

- account_processed  = processed_ids (permanent skip; also holds our own
  X-MailWarden-System mail that finding #13 leaves UNSEEN so it recurs).
- account_dry_seen   = the dry-run sidecar (empty set in real mode, so the
  second clause is a literal no-op then). In Dry Run it moves the existing
  skip-before-classify (spam_filter.py ~8836) earlier, before the wasted
  download.

The existing account_processed (~6567) and dry-run (~8836) checks REMAIN as
fallbacks: a message with a missing/unreadable Message-ID peeks as "" and
falls through to the full fetch → synthetic ID → those checks, so nothing is
ever dropped or double-processed.

Harness mirrors tests/test_finalize_seen_timing.py._run_harness (full
run_filter drive, every IO/network call mocked) but supports multiple UIDs,
a pre-seeded processed_ids AND dry-run sidecar, Dry Run on/off, and spies on
fetch_message_id / fetch_raw_email / classify_email.
"""
import email as _email
import logging as _logging
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_batch5_fetch_loop")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


def _msg(msg_id, subject="Hello there", body="Just a normal email.",
         from_email="stranger@somewhere.example", system=False):
    """One msg_data dict as extract_email_data would return. `system=True`
    attaches a real MIME object carrying X-MailWarden-System: 1 so the
    loop-top self-loop guard fires (own-mail path)."""
    d = {
        "message_id": msg_id, "from_email": from_email,
        "from_display_name": "Someone", "subject": subject,
        "plain_text_body": body, "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }
    if system:
        d["_mime_msg"] = _email.message_from_string("X-MailWarden-System: 1\n\n")
    return d


def _run(monkeypatch, *, uid_to_msg, processed_seed=None, dry_seen_seed=None,
         dry_run=False):
    """Drive spam_filter.run_filter(force=True) over an ordered
    {uid_bytes: msg_data} map. `processed_seed` / `dry_seen_seed` are lists of
    message_ids pre-loaded into processed_ids / the dry-run sidecar. Returns
    {"header_fetch": [uid,...], "body_fetch": [uid,...],
     "classified": [message_id,...], "mark_uid_seen": int,
     "processed": <final processed dict>}."""
    spies = {"header_fetch": [], "body_fetch": [], "classified": [],
             "mark_uid_seen": 0, "processed": None}

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

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)

    _proc = {"ids": {}}
    if processed_seed:
        _proc["ids"][_ACCOUNT_KEY] = [[m, "2026-07-04T00:00:00"]
                                      for m in processed_seed]
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: _proc)

    _dry = {"ids": {}}
    if dry_seen_seed:
        _dry["ids"][_ACCOUNT_KEY] = [[m, "2026-07-04T00:00:00"]
                                     for m in dry_seen_seed]
    monkeypatch.setattr(spam_filter, "load_dry_run_verdicts", lambda: _dry)
    monkeypatch.setattr(spam_filter, "persist_dry_run_verdicts",
                        lambda dv: None)

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

    def _persist(processed, tu, td):
        spies["processed"] = processed
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
                        lambda logger: {})
    monkeypatch.setattr(spam_filter, "load_rule_reviews_store",
                        lambda logger: {})
    monkeypatch.setattr(spam_filter, "append_refinement_log",
                        lambda event: None)
    monkeypatch.setattr(spam_filter, "persist_pending_merge",
                        lambda pending, touched_ids=(), **k: None)
    monkeypatch.setattr(spam_filter, "send_email", lambda *a, **k: None)

    def _seen(conn, uid, logger):
        spies["mark_uid_seen"] += 1
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    def _classify(client, system_prompt, msg_data, *a, **k):
        spies["classified"].append(msg_data.get("message_id"))
        return ({"decision": "NOT_SPAM", "confidence": 0.0,
                 "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify)
    monkeypatch.setattr(spam_filter, "execute_spam_action",
                        lambda *a, **k: "moved")

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: list(uid_to_msg))

    def _fetch_mid(conn, uid, logger):
        spies["header_fetch"].append(uid)
        return uid_to_msg[uid].get("message_id", "")
    monkeypatch.setattr(spam_filter, "fetch_message_id", _fetch_mid)

    def _fetch_raw(conn, uid, logger):
        spies["body_fetch"].append(uid)
        return b"RAW:" + uid
    monkeypatch.setattr(spam_filter, "fetch_raw_email", _fetch_raw)

    def _extract(raw, own_hosts=None):
        uid = raw.split(b":", 1)[1]
        return dict(uid_to_msg[uid])
    monkeypatch.setattr(spam_filter, "extract_email_data", _extract)

    spam_filter.run_filter(force=True)
    return spies


def _recorded(spies):
    ids = (spies["processed"] or {}).get("ids", {}).get(_ACCOUNT_KEY, [])
    return [e[0] for e in ids]


# ═════════════════════════════════════════════════════════════════════════
# #20 core: already-processed body is NOT re-downloaded; new mail IS.
# ═════════════════════════════════════════════════════════════════════════

def test_already_processed_message_body_not_refetched(monkeypatch):
    """Revert-proof anchor: a message whose Message-ID is already in
    processed_ids must be skipped header-first, WITHOUT a full-body fetch and
    WITHOUT re-classification."""
    pid = "<seen-1@example.com>"
    spies = _run(monkeypatch, uid_to_msg={b"1": _msg(pid)},
                 processed_seed=[pid])
    assert b"1" in spies["header_fetch"], "must header-peek the UID"
    assert b"1" not in spies["body_fetch"], (
        "already-processed message must NOT be full-body fetched (finding #20)")
    assert pid not in spies["classified"], (
        "already-processed message must NOT be re-classified")


def test_new_message_is_fetched_and_classified(monkeypatch):
    """A brand-new message (in neither set) MUST be full-fetched and
    classified — guards against an over-aggressive header-first skip."""
    nid = "<fresh-1@example.com>"
    spies = _run(monkeypatch, uid_to_msg={b"1": _msg(nid)})
    assert b"1" in spies["body_fetch"], (
        "a brand-new message MUST be full-body fetched")
    assert nid in spies["classified"], (
        "a brand-new message MUST be classified")


def test_mixed_batch_only_new_is_fetched(monkeypatch):
    """In one tick: the already-processed UID is skipped header-first; only the
    new UID's body is fetched and classified."""
    seen_id = "<seen-2@example.com>"
    new_id = "<fresh-2@example.com>"
    spies = _run(monkeypatch,
                 uid_to_msg={b"1": _msg(seen_id), b"2": _msg(new_id)},
                 processed_seed=[seen_id])
    assert spies["body_fetch"] == [b"2"], (
        "only the new message's body may be fetched")
    assert spies["classified"] == [new_id]


# ═════════════════════════════════════════════════════════════════════════
# #20 dry-run sidecar addition (coordinator-required): a dry-run-already-
# classified message (in account_dry_seen, Dry Run on) is skipped header-first
# WITHOUT a body fetch. Revert-proof: dropping the `or ... account_dry_seen`
# clause makes the body get fetched (then skipped at ~8836).
# ═════════════════════════════════════════════════════════════════════════

def test_dry_run_sidecar_message_skipped_header_first(monkeypatch):
    """Dry Run, message already in the dry-run sidecar: header-first skip, no
    body download, no re-classification (moves the ~8836 skip earlier)."""
    did = "<dry-spam-1@example.com>"
    spies = _run(monkeypatch, uid_to_msg={b"1": _msg(did)},
                 dry_seen_seed=[did], dry_run=True)
    assert b"1" in spies["header_fetch"]
    assert b"1" not in spies["body_fetch"], (
        "dry-run-sidecar'd message must be skipped header-first, no body "
        "download (finding #20 dry-seen addition)")
    assert did not in spies["classified"], (
        "dry-run-sidecar'd message must NOT be re-classified/re-billed")


def test_real_run_message_not_in_either_set_full_fetched(monkeypatch):
    """Real run (Dry Run off), message in NEITHER set: account_dry_seen is an
    empty set, so the second clause is a no-op and the message is full-fetched
    and classified exactly as before."""
    nid = "<real-fresh@example.com>"
    spies = _run(monkeypatch, uid_to_msg={b"1": _msg(nid)}, dry_run=False)
    assert b"1" in spies["body_fetch"], (
        "a real-run new message must be full-body fetched")
    assert nid in spies["classified"]


# ═════════════════════════════════════════════════════════════════════════
# #20 fallback: a message with no Message-ID peeks as "" and must fall through
# to the full fetch → synthetic ID → the existing checks (never dropped).
# ═════════════════════════════════════════════════════════════════════════

def test_missing_message_id_falls_back_to_full_fetch(monkeypatch):
    """Empty Message-ID -> header peek returns "" -> NOT skipped -> full fetch
    -> synthetic ID computed -> classified. Nothing is ever dropped."""
    spies = _run(monkeypatch,
                 uid_to_msg={b"1": _msg("", subject="No ID here",
                                        from_email="x@y.example")})
    assert b"1" in spies["body_fetch"], (
        "a message with no Message-ID must fall back to a full fetch")
    assert len(spies["classified"]) == 1, (
        "the no-ID message must still be classified (synthetic ID)")


# ═════════════════════════════════════════════════════════════════════════
# #13 x #20 synergy: own mail recorded processed-but-UNSEEN by finding #13
# recurs every tick; the header-first check skips it WITHOUT a body download.
# ═════════════════════════════════════════════════════════════════════════

def test_own_mail_cheaply_skipped_on_next_tick(monkeypatch):
    """Simulate the tick AFTER finding #13 recorded own mail processed-but-
    UNSEEN: its Message-ID is in processed_ids and it is still UNSEEN, so the
    header-first check skips the full body download and never re-marks it."""
    own = "<own-proposal-2@example.com>"
    spies = _run(monkeypatch,
                 uid_to_msg={b"1": _msg(own, system=True)},
                 processed_seed=[own])
    assert b"1" in spies["header_fetch"]
    assert b"1" not in spies["body_fetch"], (
        "own mail already in processed_ids must be skipped header-first "
        "(#13 x #20 synergy)")
    assert spies["mark_uid_seen"] == 0, (
        "own mail must never be marked \\Seen")

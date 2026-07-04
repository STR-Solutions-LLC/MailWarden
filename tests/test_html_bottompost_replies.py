#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Integration-audit finding #11 — HTML-only and bottom-posted owner replies
must not be silently swallowed as "our own email".

Before this fix, both reply branches extracted reply text ONLY from
plain_text_body. An HTML-only reply (no text/plain part — some webmail /
corporate clients) or a bottom-posted reply (owner's text BELOW the
"On ... wrote:" attribution, which extract_reply_text cuts) parsed as EMPTY,
was classified as MailWarden's own email, recorded processed, and dropped
with no handler, no ack, no feedback — the owner's YES/NO/APPROVE was lost.

The fix:
  * extract_reply_text_with_html_fallback — when the plain part yields no
    reply text, extract from html_to_text(html_body) instead (reuses the
    hardened Session-7 converter already on the classification hot path).
  * A reply that STILL parses empty (and is not MailWarden's own mail per
    the prefix guards) gets an honest "couldn't read your reply" ack and is
    finalized, instead of silence. Both acks go out via send_email, which
    stamps X-MailWarden-System: 1, so the loop-top guard skips them next
    tick (no ack-of-ack loop).
  * Bottom-posted replies are deliberately NOT auto-parsed (product call,
    master-adopted): scanning below the quote would let the proposal's own
    quoted "Reply YES to apply, NO to reject" line bleed into the reply,
    and classify_reply's negative-wins matching would turn a bottom-posted
    YES into a silently-executed rejection. They get the ack instead.
  * Defense-in-depth (the fix-#1 lesson): the SFID ack body names YES and
    NO, so its opening sentence is registered in _own_prefixes; the MWR ack
    keeps "APPROVE 3" strictly mid-line so the line-anchored command parser
    can never match it. Both are byte-pinned below.

Harness style mirrors tests/test_finalize_seen_timing.py's _run_harness —
a full spam_filter.run_filter(force=True) drive with every IO/network call
mocked.
"""
import inspect
import logging as _logging
import os
import sys
from datetime import datetime, timedelta

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_html_bottompost_replies")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


def _base_msg(subject, body, html_body="", from_email=_ACCOUNT_KEY,
              msg_id="<reply-1@example.com>"):
    return {
        "message_id": msg_id, "from_email": from_email,
        "from_display_name": "Owner", "subject": subject,
        "plain_text_body": body, "html_body": html_body, "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }


def _run_harness(monkeypatch, *, msg_data, pending=None,
                  approvals_store=None, patches=None):
    """Drive spam_filter.run_filter(force=True) with one UNSEEN message and
    every IO/network call mocked. Returns {"mark_uid_seen": <count>,
    "processed": <dict from persist_progress>, "send_email":
    [(subject, body, to_addr), ...]}."""
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
    simplest SFID conv_kind to drive the affirmative/negative paths end to
    end."""
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


def _approve_store(token="tok1"):
    return {token: {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": {"1": {"from_domain": "give.example",
                          "from": "News <n@give.example>",
                          "subject": "s"}},
        "rule_reviews": {},
    }}


# An HTML-only reply as real webmail clients send it: the owner's text in
# its own block, then the quoted original inside a gmail_quote div. After
# html_to_text, the attribution line lands on its own line, so
# extract_reply_text keeps the top-posted text and breaks at the quote.
def _html_reply(owner_text):
    return (
        f"<div dir=\"ltr\">{owner_text}</div>"
        "<div class=\"gmail_quote\">"
        "<div>On Fri, Jul 3, 2026 at 9:00 AM MailWarden "
        "&lt;owner@example.com&gt; wrote:</div>"
        "<blockquote>MailWarden analyzed the spam example you submitted "
        "and proposes a new refinement to add to the filter.<br>"
        "Reply YES to apply, NO to reject.<br>"
        "SFID: SFID-TEST1</blockquote></div>"
    )


# ═════════════════════════════════════════════════════════════════════════
# HTML-only replies are now processed
# ═════════════════════════════════════════════════════════════════════════

def test_htmlonly_sfid_yes_processed(monkeypatch):
    """HTML-only YES (empty plain_text_body): previously swallowed as 'our
    own email' with no feedback; must now run the affirmative handler."""
    blocked = []

    def _rec_block(value, kind, scope, logger):
        blocked.append((value, kind, scope))
        return True
    pending = _block_sender_conv()
    msg = _base_msg("Re: [SFID-TEST1] Block sender?", "",
                    html_body=_html_reply("YES"))
    calls = _run_harness(monkeypatch, msg_data=msg, pending=pending,
                        patches={"add_blocklist_entry_local": _rec_block})
    assert blocked == [("spam.example", "domain", "all")], (
        "HTML-only YES must apply the block-sender proposal")
    assert pending["conversations"][0]["status"] == "approved"
    assert calls["mark_uid_seen"] == 1
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "Sender blocked" in subject


def test_htmlonly_sfid_no_processed(monkeypatch):
    """HTML-only NO must run the negative handler (proposal rejected +
    rejection ack), proving classify_reply sees the HTML-extracted text."""
    pending = _block_sender_conv()
    msg = _base_msg("Re: [SFID-TEST1] Block sender?", "",
                    html_body=_html_reply("NO"))
    calls = _run_harness(monkeypatch, msg_data=msg, pending=pending)
    assert pending["conversations"][0]["status"] == "rejected"
    assert calls["mark_uid_seen"] == 1
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "Rejected" in subject


def test_htmlonly_mwr_approve_processed(monkeypatch):
    """HTML-only 'APPROVE 1' reply to a daily report: previously swallowed;
    must now approve the sender domain and ack."""
    approved = []

    def _rec(domain, logger):
        approved.append(domain)
        return True
    msg = _base_msg("Re: MailWarden Report — July 03 [MWR-tok1]", "",
                    html_body=(
                        "<div dir=\"ltr\">APPROVE 1</div>"
                        "<div class=\"gmail_quote\">"
                        "<div>On Fri, Jul 3, 2026 at 7:00 AM MailWarden "
                        "&lt;owner@example.com&gt; wrote:</div>"
                        "<blockquote>SPAM FILTER DAILY REPORT<br>"
                        "1. News &lt;n@give.example&gt; — s</blockquote>"
                        "</div>"))
    calls = _run_harness(monkeypatch, msg_data=msg,
                        approvals_store=_approve_store(),
                        patches={"add_approved_domain": _rec})
    assert approved == ["give.example"], (
        "HTML-only APPROVE 1 must approve the item's sender domain")
    assert calls["mark_uid_seen"] == 1
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "Sender approval" in subject


# ═════════════════════════════════════════════════════════════════════════
# MailWarden's own mail must stay unprocessable
# ═════════════════════════════════════════════════════════════════════════

def test_daily_report_own_body_never_processed(monkeypatch):
    """The daily report itself (plain-text only, body starts 'SPAM FILTER
    DAILY REPORT', carries the [MWR-...] subject and an instruction line
    naming APPROVE) must still be skipped record-only and left UNSEEN —
    no handler, no ack, no approval."""
    approved = []

    def _rec(domain, logger):
        approved.append(domain)
        return True
    report_body = (
        "SPAM FILTER DAILY REPORT\n"
        "July 03, 2026 — 7:00 AM\n"
        "========================================\n\n"
        "JUNK MAIL BLOCKED\n"
        "1. News <n@give.example> — s\n\n"
        "To approve a sender, reply APPROVE and the item number "
        "(for example APPROVE 1).\n")
    msg = _base_msg("MailWarden Report — July 03 [MWR-tok1]", report_body)
    calls = _run_harness(monkeypatch, msg_data=msg,
                        approvals_store=_approve_store(),
                        patches={"add_approved_domain": _rec})
    assert approved == [], "the report's own body must never approve anything"
    assert len(calls["send_email"]) == 0, (
        "the report's own body must never trigger an ack")
    assert calls["mark_uid_seen"] == 0, (
        "the report must stay UNSEEN so the owner still reads it")
    assert msg["message_id"] in _msg_ids_recorded(calls), (
        "the report must still be recorded processed (loop prevention)")


def test_own_sfid_analysis_still_skipped(monkeypatch):
    """MailWarden's own outgoing SFID analysis email (recognized by its
    _own_prefixes opening line, unstamped to exercise the defense-in-depth
    arm directly) must still be skipped silently: record-only, left UNSEEN,
    no ack, conversation untouched.

    Subject deliberately does NOT start with "False Positive ..." — that
    prefix-matches the email-command table BEFORE the SFID branch runs
    (finding #14, separate fix) and would route this fixture into the FP
    teach handler instead of the prefix arm under test."""
    pending = _block_sender_conv()
    msg = _base_msg(
        "Re: [SFID-TEST1] Block sender?",
        "Your false positive has been analyzed and a signal change is "
        "proposed below.\n\nReply YES to apply, NO to reject.\n")
    calls = _run_harness(monkeypatch, msg_data=msg, pending=pending)
    assert len(calls["send_email"]) == 0, (
        "own analysis email must not trigger any reply")
    assert calls["mark_uid_seen"] == 0, (
        "own analysis email must stay UNSEEN (finding #13)")
    assert msg["message_id"] in _msg_ids_recorded(calls)
    assert pending["conversations"][0]["status"] == "awaiting_reply"


# ═════════════════════════════════════════════════════════════════════════
# Still-unreadable replies get the could-not-read ack (not silence)
# ═════════════════════════════════════════════════════════════════════════

def test_empty_sfid_reply_gets_could_not_read_ack(monkeypatch):
    """A genuinely-empty owner reply (no plain text, no HTML) must get the
    could-not-read ack and be finalized — never applied, never rejected,
    never silently dropped."""
    pending = _block_sender_conv()
    msg = _base_msg("Re: [SFID-TEST1] Block sender?", "")
    calls = _run_harness(monkeypatch, msg_data=msg, pending=pending)
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "couldn't read your reply" in subject
    assert body == spam_filter._SFID_UNREADABLE_REPLY_BODY.format(
        sfid="SFID-TEST1")
    assert to_addr == _ACCOUNT_KEY
    assert calls["mark_uid_seen"] == 1, "ack path must finalize (mark Seen)"
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1
    assert pending["conversations"][0]["status"] == "awaiting_reply", (
        "an unreadable reply must not resolve the proposal")


def test_empty_mwr_reply_gets_could_not_read_ack(monkeypatch):
    """A genuinely-empty reply to a daily report must get the MWR
    could-not-read ack and be finalized; no sender approved."""
    approved = []

    def _rec(domain, logger):
        approved.append(domain)
        return True
    msg = _base_msg("Re: MailWarden Report — July 03 [MWR-tok1]", "")
    calls = _run_harness(monkeypatch, msg_data=msg,
                        approvals_store=_approve_store(),
                        patches={"add_approved_domain": _rec})
    assert approved == []
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "couldn't read your reply" in subject
    assert body == spam_filter._MWR_UNREADABLE_REPLY_BODY
    assert calls["mark_uid_seen"] == 1
    assert _msg_ids_recorded(calls).count(msg["message_id"]) == 1


def test_bottom_posted_sfid_reply_gets_ack_not_misclassified(monkeypatch):
    """Bottom-posted YES (owner's text BELOW the unquoted attribution line,
    the shape most clients produce). Auto-parsing it is deliberately out of
    scope: the quoted 'Reply YES to apply, NO to reject' instruction would
    bleed into the reply and classify_reply's negative-wins matching would
    execute a REJECTION the owner never sent. The safe contract: the
    proposal is neither applied nor rejected, and the owner gets the
    could-not-read ack telling them to reply above the quote."""
    blocked = []

    def _rec_block(value, kind, scope, logger):
        blocked.append(value)
        return True
    pending = _block_sender_conv()
    msg = _base_msg(
        "Re: [SFID-TEST1] Block sender?",
        "On Fri, Jul 3, 2026 at 9:00 AM MailWarden <owner@example.com> wrote:\n"
        "> MailWarden proposes blocking spam.example.\n"
        "> Reply YES to apply, NO to reject.\n"
        "> SFID: SFID-TEST1\n"
        "\n"
        "YES\n")
    calls = _run_harness(monkeypatch, msg_data=msg, pending=pending,
                        patches={"add_blocklist_entry_local": _rec_block})
    assert blocked == [], "bottom-posted YES must not be guessed and applied"
    assert pending["conversations"][0]["status"] == "awaiting_reply", (
        "bottom-posted YES must be neither applied nor rejected")
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert "couldn't read your reply" in subject
    assert calls["mark_uid_seen"] == 1


# ═════════════════════════════════════════════════════════════════════════
# Byte-pinning: the acks must never become processable as replies/commands
# ═════════════════════════════════════════════════════════════════════════

def test_sfid_ack_opening_sentence_pinned_in_own_prefixes():
    """The SFID could-not-read ack names YES and NO. If the
    X-MailWarden-System stamp were ever lost, classify_reply would read the
    ack as 'negative' and could act on it — so the ack's exact opening
    sentence must be registered in run_filter's _own_prefixes, and the body
    must actually start with that registered prefix. Pins both bytes: fails
    loudly if either side's wording drifts (mirrors the 4f3d385 /
    test_session8.py pinning tests)."""
    prefix = ("MailWarden received your reply but couldn't read any "
              "instruction in it.")
    src = inspect.getsource(spam_filter.run_filter)
    assert prefix in src, (
        "SFID could-not-read ack opening sentence not in _own_prefixes — "
        "self-loop risk if the system-header stamp is ever lost")
    assert spam_filter._SFID_UNREADABLE_REPLY_BODY.startswith(prefix), (
        "_SFID_UNREADABLE_REPLY_BODY no longer starts with the sentence "
        "registered in _own_prefixes — the prefix guard would miss it")


def test_mwr_ack_body_never_parses_as_a_command():
    """No _own_prefixes list exists for [MWR-...] mail, so the MWR ack's
    defense is structural: 'APPROVE 3' must stay strictly mid-line, because
    _parse_command_numbers only matches a verb that STARTS a line. Pin the
    full body against every reply parser it could re-enter."""
    body = spam_filter._MWR_UNREADABLE_REPLY_BODY
    assert spam_filter.parse_approve_command(body) == [], (
        "the MWR could-not-read ack parses as an APPROVE command — "
        "self-trigger risk if the system-header stamp is ever lost")
    assert spam_filter.parse_rule_review_command(body) is None
    # Same guarantee after reply extraction (how the branch would see it).
    extracted = spam_filter.extract_reply_text(body)
    assert spam_filter.parse_approve_command(extracted) == []
    # Structural pin: APPROVE must never begin a line of the ack body.
    for line in body.splitlines():
        assert not line.lstrip().lower().startswith("approve"), (
            f"'APPROVE' begins a line of _MWR_UNREADABLE_REPLY_BODY: "
            f"{line!r} — _parse_command_numbers could match it")

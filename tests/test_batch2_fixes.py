#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Batch 2 integration-audit fixes.

Finding #14 — a FORWARD of one of MailWarden's own false-positive analysis
emails still carries the original [SFID-...] token; after its Fwd:/Re:
prefixes are stripped it re-matches the "False Positive" command and used to
mint a brand-new bogus SFID (and run a wasted analysis on our own output). The
fix guards the FP-teach handler: if the incoming subject already carries one of
our own [SFID-...]/[MWR-...] tokens, redirect the owner honestly instead of
minting. A genuine REPLY keeps its leading "Re:" (only a Fwd: enables
Re:-stripping), so detect_email_command returns None for it and it never
reaches this handler — the reply corridor is untouched.

Finding #5 — the FP-teach analysis handler and the FP follow-up handler used to
swallow API failures (log only; no email to the owner). The fix mirrors the
SPAM-example convention: on failure, send the owner an honest ack. No retry —
the message is still finalized, so the analysis is not re-billed every tick.

All message bodies here are structure-only dummies — never real owner content.
"""
import os
import sys
from datetime import datetime, timedelta

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402
from test_fixes import _dry_run_filter_harness  # noqa: E402


# --- message builders -------------------------------------------------------

def _forwarded_analysis_msg(token="SFID-20260101-abcd"):
    """Owner FORWARDS one of MailWarden's own analysis emails back to it.
    Client keeps the original subject (token intact) and prefixes 'Fwd: '."""
    return {
        "message_id": "<fwd-analysis-1@example.com>",
        "from_email": "owner@example.com",
        "from_display_name": "Owner",
        "subject": f"Fwd: Re: False Positive Analysis [{token}] — Receipt",
        # Forward preamble sits ABOVE the quoted analysis, so this does NOT
        # start with an _own_prefixes sentence (realistic).
        "plain_text_body": (
            "---------- Forwarded message ----------\n"
            "From: MailWarden <owner@example.com>\n"
            "Subject: Re: False Positive Analysis [%s] — Receipt\n\n"
            "Your false positive has been analyzed.\n"
            "WHY IT WAS FLAGGED:\n...\n" % token
        ),
        "html_body": "",
        "_mime_msg": None,
    }


def _fresh_fp_teach_msg():
    """Owner forwards a genuinely-filtered email as a NEW false positive.
    Subject carries no token, so a fresh analysis should be minted."""
    return {
        "message_id": "<fresh-fp-1@example.com>",
        "from_email": "owner@example.com",
        "from_display_name": "Owner",
        "subject": "Fwd: False Positive",
        "plain_text_body": (
            "Please review.\n\nBegin forwarded message:\n"
            "From: Vendor <vendor@example.com>\nSubject: Your receipt\n"
            "Date: Mon, 19 Apr 2026 09:00:00 -0700\n\n"
            "Thanks for your order.\n"
        ),
        "html_body": "",
        "_mime_msg": None,
    }


def _followup_reply_msg(token="SFID-FPX1"):
    """Owner replies to an analysis email with a QUESTION (not YES/NO)."""
    return {
        "message_id": "<followup-1@example.com>",
        "from_email": "owner@example.com",
        "from_display_name": "Owner",
        "subject": f"Re: False Positive Analysis [{token}] — Receipt",
        "plain_text_body": "How much spam might slip through with this change?",
        "html_body": "",
        "_mime_msg": None,
    }


def _open_fp_conv(sfid="SFID-FPX1"):
    return {
        "id": sfid,
        "kind": "false_positive",
        "status": "awaiting_reply",
        "expires": (datetime.now() + timedelta(days=7)).isoformat(),
        "original_subject": "Receipt",
        "api_analysis": "WHY IT WAS FLAGGED:\nx\n",
        "proposed_changes": {"signals_to_narrow": {"from_analysis": "narrow it"}},
        "conversation_history": [],
        "resolution": None,
    }


# ===========================================================================
# Finding #14
# ===========================================================================

def test_own_analysis_token_re_matches():
    """Unit: the guard regex recognises our own bracketed tokens only."""
    r = spam_filter._OWN_ANALYSIS_TOKEN_RE
    assert r.search("Fwd: Re: X [SFID-20260101-abcd] — Y")
    assert r.search("Fwd: report [MWR-20260101-xy]")
    assert not r.search("Fwd: False Positive")
    assert not r.search("Re: an ordinary subject")


def test_forwarded_analysis_does_not_mint_new_sfid(monkeypatch):
    """REVERT-PROOF (#14): forwarding our own analysis email must NOT mint a
    new SFID and must NOT spend a billed API call — it must redirect honestly.
    Reverting the guard mints a conversation and calls the API → this fails."""
    monkeypatch.setattr(spam_filter, "lookup_decision", lambda *a, **k: None)
    pending = {"conversations": []}
    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_forwarded_analysis_msg(),
        dry_run=False, pending=pending)

    assert pending["conversations"] == [], "must not mint a new conversation"
    assert calls["messages_create_kwargs"] == [], "must not spend an API call"
    assert calls["mark_uid_seen"] >= 1, "must finalize (mark \\Seen)"
    subjects = [s for (s, _b) in calls["send_email_args"]]
    assert subjects == ["MailWarden analysis email — no new analysis started"]
    body = calls["send_email_args"][0][1]
    assert "[SFID-20260101-abcd]" in body


def test_genuine_reply_still_reaches_sfid_branch(monkeypatch):
    """SUBTLETY (#14): a genuine REPLY (leading 'Re:', no Fwd:) must still be
    handled by the SFID reply branch and must NOT be treated as a fresh teach.
    Proves the guard cannot suppress replies (and that a naive
    subject-token guard placed in detect_email_command would be wrong)."""
    pending = {"conversations": [_open_fp_conv("SFID-FPX1")]}
    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_followup_reply_msg("SFID-FPX1"),
        dry_run=False, pending=pending)

    assert len(pending["conversations"]) == 1, "no bogus new conversation"
    conv = pending["conversations"][0]
    assert any(h.get("role") == "user_reply" and "slip through" in h.get("content", "")
               for h in conv["conversation_history"]), \
        "reply must be recorded by the SFID reply branch"
    subjects = [s for (s, _b) in calls["send_email_args"]]
    assert any("[SFID-FPX1]" in s for s in subjects), \
        "follow-up answer must be sent under the same SFID"


def test_fresh_fp_teach_still_mints(monkeypatch):
    """REGRESSION (#14): a genuine fresh teach (no token in subject) must still
    mint a conversation and call the analysis API — the guard must not suppress
    it."""
    monkeypatch.setattr(spam_filter, "lookup_decision", lambda *a, **k: None)
    pending = {"conversations": []}
    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_fresh_fp_teach_msg(),
        dry_run=False, pending=pending)

    assert len(pending["conversations"]) == 1, "fresh teach must mint"
    assert len(calls["messages_create_kwargs"]) == 1, "fresh teach must call API"


# ===========================================================================
# Finding #5
# ===========================================================================

def test_fp_teach_api_failure_acks_owner(monkeypatch):
    """REVERT-PROOF (#5a): when the analysis API fails, the owner must get an
    honest ack (was: silently swallowed). Reverting the fix sends zero emails
    → this fails."""
    monkeypatch.setattr(spam_filter, "lookup_decision", lambda *a, **k: None)
    pending = {"conversations": []}
    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_fresh_fp_teach_msg(),
        dry_run=False, pending=pending, api_raises=True)

    assert len(calls["messages_create_kwargs"]) == 1, "API was attempted"
    assert pending["conversations"] == [], "no conversation on failed analysis"
    assert calls["mark_uid_seen"] >= 1, "must finalize (no re-bill)"
    acks = [(s, b) for (s, b) in calls["send_email_args"]
            if s == "MailWarden couldn't run that false-positive analysis"]
    assert len(acks) == 1, "exactly one honest failure ack"
    assert acks[0][1] == spam_filter._FP_ANALYSIS_FAILED_BODY


def test_fp_followup_api_failure_acks_owner(monkeypatch):
    """REVERT-PROOF (#5b): when the follow-up API fails, the owner must get an
    honest ack and the proposal must stay open. Reverting the fix sends zero
    emails → this fails."""
    pending = {"conversations": [_open_fp_conv("SFID-FPX1")]}
    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_followup_reply_msg("SFID-FPX1"),
        dry_run=False, pending=pending, api_raises=True)

    assert len(calls["messages_create_kwargs"]) == 1, "follow-up API attempted"
    conv = pending["conversations"][0]
    assert conv["status"] == "awaiting_reply", "proposal must stay open"
    assert calls["mark_uid_seen"] >= 1, "must finalize (no re-bill)"
    acks = [(s, b) for (s, b) in calls["send_email_args"]
            if b == spam_filter._FP_FOLLOWUP_FAILED_BODY.format(sfid="SFID-FPX1")]
    assert len(acks) == 1, "exactly one honest follow-up failure ack"
    assert acks[0][0] == "Re: False Positive Analysis [SFID-FPX1] — Receipt"


def test_followup_failed_ack_opening_in_own_prefixes():
    """Self-loop pin: the follow-up failure ack names YES/NO under an
    [SFID-...] subject, so its opening sentence must be registered in
    run_filter's _own_prefixes AND the body must start with it (mirrors the
    SFID could-not-read ack pin)."""
    import inspect
    prefix = "MailWarden couldn't answer your question right now."
    src = inspect.getsource(spam_filter.run_filter)
    assert prefix in src, (
        "Follow-up failure ack opening sentence not in _own_prefixes — "
        "self-loop risk if the X-MailWarden-System stamp is ever lost")
    assert spam_filter._FP_FOLLOWUP_FAILED_BODY.startswith(prefix), (
        "_FP_FOLLOWUP_FAILED_BODY no longer starts with the registered "
        "sentence — the prefix guard would miss it")

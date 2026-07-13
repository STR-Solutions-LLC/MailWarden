#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Owner-mail junking exemption ("never junk mail from me").

A NON-command message whose From is one of the owner's own identities must
NEVER be junked when it can be trusted as genuinely from the owner. This is a
high-precedence CLASSIFICATION exemption that outranks every junking gate
(blacklist address/name/domain, subject-keyword, pre-classifier tripwires, and
AI/curate rules). It is separate from — and does not change — the email-COMMAND
path.

These tests pin the decision function spam_filter._is_protected_owner_mail
across the full authentication ladder, and source-inspect run_filter to prove
the exemption is wired in as the highest-precedence junking gate (before the
blacklist, subject-keyword, and AI-classify calls) and routes to a
leave-in-inbox `continue`.

NO real API / IMAP / SMTP calls. Received chains are built as real parsed MIME
messages, mirroring tests/test_fixes.py's path-(b) fixtures.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_owner_mail_exemption.py -v
"""
import email as _email
import inspect
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures: an owner whose own mail host is box5275.bluehost.com (as in prod).
# ---------------------------------------------------------------------------
_OWNER = "matt@nthmonkey.com"
_OWNER_DOMAIN = "nthmonkey.com"
_ACCOUNT = {"name": "Main", "username": _OWNER, "enabled": True,
            "imap_host": "box5275.bluehost.com",
            "junk_folder": "Junk"}
_CONFIG = {
    "accounts": [_ACCOUNT],
    "smtp": {"host": "box5275.bluehost.com",
             "username": _OWNER, "from_address": _OWNER},
    "filter": {"dry_run": True},
}

# A body that WOULD otherwise be junked — spammy subject-keyword / curate-bait
# content. The exemption must win regardless of body.
_SPAM_LIKE_BODY = ("VIAGRA CIALIS best prices!!! Click here to claim your "
                   "FREE prize now — limited time offer, act fast!!!\n")

# Aligned Gmail-style Authentication-Results proving SPF+DKIM+DMARC pass for the
# owner's own From-domain (path (a)).
_ALIGNED_AR = (
    "mx.google.com; "
    "dkim=pass header.i=@nthmonkey.com header.s=sel header.b=AbCdEf; "
    "spf=pass (google.com: domain of bounce@nthmonkey.com designates "
    "1.2.3.4 as permitted sender) smtp.mailfrom=bounce@nthmonkey.com; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nthmonkey.com"
)


def _md(*, auth_results="", received_spf="", dkim_signature="",
        received_block=None, body=_SPAM_LIKE_BODY):
    """Build a msg_data dict. When *received_block* is given it is parsed into a
    real _mime_msg (so _submitted_via_own_server / _has_received_chain see a real
    Received chain); otherwise _mime_msg is a body-only message with NO Received
    headers."""
    if received_block is not None:
        raw = received_block.rstrip("\n") + "\n\n" + body
    else:
        raw = "\n" + body  # no headers at all
    msg = _email.message_from_string(raw)
    return {
        "from_email": _OWNER,
        "from_display_name": "Matt",
        "auth_results": auth_results,
        "received_spf": received_spf,
        "dkim_signature": dkim_signature,
        "plain_text_body": body,
        "_mime_msg": msg,
    }


# ---------------------------------------------------------------------------
# 1. Path (a): SPF/DKIM-aligned pass -> exempt even with junk-worthy content.
# ---------------------------------------------------------------------------
def test_owner_path_a_aligned_pass_is_exempt():
    md = _md(auth_results=_ALIGNED_AR, body=_SPAM_LIKE_BODY)
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is True
    assert path == "a"


# ---------------------------------------------------------------------------
# 2. Path (b): authenticated submission through own server, NO SPF/DKIM/AR.
# ---------------------------------------------------------------------------
def test_owner_path_b_own_server_submission_is_exempt():
    received = (
        "Received: from box5275.bluehost.com by box5275.bluehost.com with LMTP "
        "id abc123 for <matt@nthmonkey.com>\n"
        "Received: from [72.80.205.252] (port=56467 helo=[192.168.1.202]) "
        "by box5275.bluehost.com with esmtpsa (TLS1.3) tls "
        "TLS_AES_256_GCM_SHA384 (Exim 4.99.2) "
        "(envelope-from <matt@nthmonkey.com>) id def456 for matt@nthmonkey.com"
    )
    md = _md(received_block=received)  # no auth headers at all
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is True
    assert path == "b"


# ---------------------------------------------------------------------------
# 3. Authentication PRESENT but FAILED (spf=fail), NOT via own server -> NOT
#    exempt (spoof/broken case, stays filterable).
# ---------------------------------------------------------------------------
def test_owner_auth_present_failed_is_not_exempt():
    failed_ar = ("mx.google.com; spf=fail (google.com: domain of "
                 "matt@nthmonkey.com does not designate 9.9.9.9 as permitted "
                 "sender) smtp.mailfrom=matt@nthmonkey.com; dkim=none; "
                 "dmarc=fail header.from=nthmonkey.com")
    # Foreign Received chain (delivered by a host that is NOT our own server).
    received = ("Received: from evil.example (evil.example [9.9.9.9]) "
                "by mx.google.com with esmtps id xyz for <matt@nthmonkey.com>")
    md = _md(auth_results=failed_ar, received_block=received)
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is False
    assert path == ""


# ---------------------------------------------------------------------------
# 4. Authentication ENTIRELY ABSENT + no own-server Received evidence -> exempt
#    (absent-host fallback: trust the From).
# ---------------------------------------------------------------------------
def test_owner_absent_auth_no_received_is_exempt():
    md = _md()  # no auth headers, no Received chain (IMAP-APPEND-like)
    assert spam_filter._has_received_chain(md) is False  # sanity
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is True
    assert path == "absent-fallback"


def test_absent_auth_but_foreign_received_chain_is_not_exempt():
    """Guard against the strip-the-headers spoof: absent auth but a REAL foreign
    Received chain is evidence the mail traversed servers and did NOT prove the
    owner — the absent-host fallback must NOT fire."""
    received = ("Received: from evil.example (evil.example [9.9.9.9]) "
                "by mx.foreign.example with esmtp id q1 for <matt@nthmonkey.com>")
    md = _md(received_block=received)  # foreign chain, no auth headers
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is False
    assert path == ""


# ---------------------------------------------------------------------------
# 5. THE BUG SCENARIO: owner-sent mail that quotes spam content AND would match
#    an active AI curate rule -> now exempt when owner-authenticated. Modeled
#    via path (a) so no live API call is needed; the exemption runs BEFORE the
#    AI/curate gate (see the precedence test below), so the curate rule never
#    gets to junk it.
# ---------------------------------------------------------------------------
def test_owner_mail_quoting_spam_is_exempt_over_curate():
    quoting_body = (
        "Heads up team — forwarding this junk we keep getting so we can add a "
        "rule:\n\n> Unwanted-Category: crypto pump-and-dump — BUY $DOGE NOW!!! "
        "guaranteed 100x returns, click to join our signals group\n")
    md = _md(auth_results=_ALIGNED_AR, body=quoting_body)
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is True
    assert path == "a"


# ---------------------------------------------------------------------------
# 6. REGRESSION: a stranger (From NOT an owner identity) is unaffected — never
#    exempt, no matter how their mail authenticates.
# ---------------------------------------------------------------------------
def test_stranger_is_never_exempt():
    stranger = "stranger@evil.example"
    stranger_aligned = (
        "mx.google.com; dkim=pass header.i=@evil.example header.s=s; "
        "spf=pass smtp.mailfrom=stranger@evil.example; "
        "dmarc=pass header.from=evil.example")
    md = _md(auth_results=stranger_aligned, body=_SPAM_LIKE_BODY)
    md["from_email"] = stranger
    protected, path = spam_filter._is_protected_owner_mail(
        md, stranger, _ACCOUNT, _CONFIG)
    assert protected is False
    assert path == ""


def test_stranger_absent_auth_is_never_exempt():
    """Even a stranger with no auth headers and no Received chain (which for the
    OWNER would trigger the absent-host fallback) is not exempt."""
    stranger = "stranger@evil.example"
    md = _md()
    md["from_email"] = stranger
    protected, path = spam_filter._is_protected_owner_mail(
        md, stranger, _ACCOUNT, _CONFIG)
    assert protected is False
    assert path == ""


# ---------------------------------------------------------------------------
# 7. Spoofed From = owner address but auth fails -> NOT exempt (still filterable).
# ---------------------------------------------------------------------------
def test_spoofed_owner_from_with_failing_auth_is_not_exempt():
    # From LOOKS like the owner, but SPF/DMARC fail and it did not come through
    # the owner's own server — a spoof. Must remain junkable.
    spoof_ar = ("mx.google.com; spf=softfail smtp.mailfrom=x@nthmonkey.com; "
                "dkim=fail header.i=@nthmonkey.com; "
                "dmarc=fail header.from=nthmonkey.com")
    received = ("Received: from spammer.example (spammer.example [6.6.6.6]) "
                "by mx.google.com with esmtps id s1 for <matt@nthmonkey.com>")
    md = _md(auth_results=spoof_ar, received_block=received)
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is False
    assert path == ""


# ---------------------------------------------------------------------------
# Precedence wiring: prove the exemption is the FIRST junking gate in run_filter
# and short-circuits to a leave-in-inbox continue.
# ---------------------------------------------------------------------------
def test_exemption_runs_before_all_junking_gates():
    src = inspect.getsource(spam_filter.run_filter)
    assert "_is_protected_owner_mail(" in src
    at = src.index("_is_protected_owner_mail(")
    # It must precede every downstream junking gate.
    assert at < src.index("check_blacklist("), "must precede blacklist gate"
    assert at < src.index("check_subject_keywords("), "must precede keyword gate"
    assert at < src.index("classify_email"), "must precede AI classify call"
    # And it must precede the whitelist gate too (it is precedence check 0).
    assert at < src.index("check_whitelist_address_only(")


def test_exemption_short_circuits_to_leave_in_inbox():
    """The exemption branch ends in a `continue` (leave in inbox) and marks the
    message processed — it never falls through into a junking action."""
    src = inspect.getsource(spam_filter.run_filter)
    start = src.index("owner_protected, owner_path = _is_protected_owner_mail(")
    # Look at the ~30 lines that make up the exemption branch.
    branch = src[start:start + 1400]
    assert "if owner_protected:" in branch
    assert "exempt from junking" in branch  # the required INFO log line
    assert "_record_processed(" in branch
    assert "continue" in branch
    # It must NOT invoke a spam/junk action inside the exemption branch.
    upto_continue = branch[:branch.index("continue")]
    assert "execute_spam_action(" not in upto_continue


# ---------------------------------------------------------------------------
# Extraction integrity: _command_auth_ok still delegates path (b) to the shared
# helper (so command auth and the exemption use identical own-server logic), and
# command auth remains strict (no absent-host fallback).
# ---------------------------------------------------------------------------
def test_command_auth_delegates_to_shared_own_server_helper():
    src = inspect.getsource(spam_filter._command_auth_ok)
    assert "_submitted_via_own_server(msg_data, account, config)" in src


def test_command_auth_has_no_absent_host_fallback():
    """Commands stay strict: a genuine-looking owner From with NO auth data and
    NO Received chain must FAIL command auth (only the junking exemption gets the
    absent-host fallback)."""
    md = {"auth_results": "", "received_spf": "", "dkim_signature": "",
          "_mime_msg": _email.message_from_string("\nbody\n")}
    assert spam_filter._command_auth_ok(md, _OWNER, _ACCOUNT, _CONFIG) is False
    # But the exemption DOES trust that same message (absent-host fallback).
    protected, path = spam_filter._is_protected_owner_mail(
        md, _OWNER, _ACCOUNT, _CONFIG)
    assert protected is True and path == "absent-fallback"

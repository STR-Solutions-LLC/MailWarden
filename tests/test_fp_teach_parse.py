#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Regression + unit tests for the false-positive teach flow.

Root bug (pre-existing since 34ceb39 / 46b5ccbd): the FP-analysis prompt asks
for bare section labels ("PROPOSED CHANGE:" …) but the current model emits
Markdown headings ("## PROPOSED CHANGE:"). The old parser's lookaheads required
a bare label right after "\n", so the parse produced an EMPTY proposed_changes;
on YES the legacy handler wrote nothing yet unconditionally acked "applied",
silently destroying the proposal.

Fix 1 — tolerant parsing (Markdown heading / bold dressing) via
         spam_filter._parse_fp_proposed_changes.
Fix 2 — verify-before-ack in the YES handler: an unappliable proposal stays
         pending, logs an honest 'apply_failed' event, and sends a truthful ack
         instead of the false "Signal Update Applied".

No real owner email content is embedded here; the Markdown fixture is
structure-identical dummy content.
"""
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402
from test_fixes import _dry_run_filter_harness  # noqa: E402


# --- Structure-identical dummy analyses (never real owner content) ----------

# The exact production failure shape: every section label carries a Markdown
# heading prefix, which the OLD parser could not match.
MARKDOWN_HEADING_ANALYSIS = (
    "## WHY IT WAS FLAGGED:\n"
    "The bulk-sender and promo-keyword signals both matched.\n\n"
    "## WHY THE USER IS RIGHT:\n"
    "It is a transactional receipt from a vendor the owner uses.\n\n"
    "## PROPOSED CHANGE:\n"
    "Narrow the promo-keyword signal to exclude order-receipt subjects.\n\n"
    "## TRADEOFF:\n"
    "A little promotional spam using receipt wording may slip through.\n\n"
    "## MY RECOMMENDATION:\n"
    "Apply it; the risk is low.\n"
)

BARE_LABEL_ANALYSIS = (
    "WHY IT WAS FLAGGED:\nx\n\n"
    "PROPOSED CHANGE:\nnarrow the widget signal\n\n"
    "TRADEOFF:\nlow risk\n\n"
    "MY RECOMMENDATION:\napply\n"
)


# ===========================================================================
# (D) unit tests — pure parser (no I/O)
# ===========================================================================

def test_parse_markdown_heading_production_shape():
    """REGRESSION: the exact production failure shape must now parse to a
    non-empty proposed change + tradeoff (empty before the fix)."""
    out = spam_filter._parse_fp_proposed_changes(MARKDOWN_HEADING_ANALYSIS)
    assert out["signals_to_narrow"].get("from_analysis") == (
        "Narrow the promo-keyword signal to exclude order-receipt subjects.")
    assert out["tradeoffs"] == (
        "A little promotional spam using receipt wording may slip through.")


def test_parse_bare_label_unchanged():
    """The original bare-label contract still parses byte-identically."""
    out = spam_filter._parse_fp_proposed_changes(BARE_LABEL_ANALYSIS)
    assert out["signals_to_narrow"].get("from_analysis") == "narrow the widget signal"
    assert out["tradeoffs"] == "low risk"


def test_parse_bold_colon_inside():
    out = spam_filter._parse_fp_proposed_changes(
        "**PROPOSED CHANGE:**\nnarrow X\n\n"
        "**TRADEOFF:**\nlow\n\n**MY RECOMMENDATION:**\nyes")
    assert out["signals_to_narrow"].get("from_analysis") == "narrow X"
    assert out["tradeoffs"] == "low"


def test_parse_bold_colon_outside():
    out = spam_filter._parse_fp_proposed_changes(
        "**PROPOSED CHANGE**:\nnarrow X\n\n"
        "**TRADEOFF**:\nlow\n\n**MY RECOMMENDATION**:\nyes")
    assert out["signals_to_narrow"].get("from_analysis") == "narrow X"
    assert out["tradeoffs"] == "low"


def test_parse_heading_bold_inline_content():
    out = spam_filter._parse_fp_proposed_changes(
        "### **PROPOSED CHANGE:** narrow Y here\n\n"
        "### **TRADEOFF:** minimal\n\n"
        "### **MY RECOMMENDATION:** apply")
    assert out["signals_to_narrow"].get("from_analysis") == "narrow Y here"
    assert out["tradeoffs"] == "minimal"


def test_parse_heading_no_colon():
    out = spam_filter._parse_fp_proposed_changes(
        "## PROPOSED CHANGE\nnarrow Z\n\n"
        "## TRADEOFF\nnone\n\n## MY RECOMMENDATION\ngo")
    assert out["signals_to_narrow"].get("from_analysis") == "narrow Z"
    assert out["tradeoffs"] == "none"


def test_parse_prose_labels_not_matched():
    """A bare, colon-less label inside prose must NOT be treated as a section
    boundary — guards against over-eager matching."""
    out = spam_filter._parse_fp_proposed_changes(
        "PROPOSED CHANGE ideas are discussed below.\n"
        "TRADEOFF analysis suggests caution.\nNothing structured here.")
    assert out["signals_to_narrow"] == {}
    assert out["tradeoffs"] == ""


def test_parse_missing_sections_empty():
    out = spam_filter._parse_fp_proposed_changes(
        "WHY IT WAS FLAGGED:\nx\n\nMY RECOMMENDATION:\nre-teach")
    assert out["signals_to_narrow"] == {}


def test_fp_changes_appliable_truth_table():
    assert spam_filter._fp_changes_appliable(
        {"signals_to_narrow": {"from_analysis": "narrow it"}}) is True
    assert spam_filter._fp_changes_appliable(
        {"signals_to_narrow": {}}) is False
    assert spam_filter._fp_changes_appliable({}) is False
    assert spam_filter._fp_changes_appliable(
        {"signals_to_narrow": {"from_analysis": "   "}}) is False
    assert spam_filter._fp_changes_appliable(None) is False


# ===========================================================================
# (D) end-to-end tests via the shared run_filter harness
# ===========================================================================

def _fp_forward_msg():
    """Parsed 'Fwd: False Positive' owner message that triggers FP analysis."""
    return {
        "message_id": "<fp-teach-1@example.com>",
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


def _yes_reply_msg(sfid):
    return {
        "message_id": "<yes-1@example.com>",
        "from_email": "owner@example.com",
        "from_display_name": "Owner",
        "subject": f"Re: [{sfid}] please",
        "plain_text_body": "YES approve this please",
        "html_body": "",
        "_mime_msg": None,
    }


def _apply_failed_events(monkeypatch):
    """Install an append_refinement_log spy; return the recorded events list."""
    events = []
    monkeypatch.setattr(spam_filter, "append_refinement_log",
                        lambda ev: events.append(ev))
    return events


def test_e2e_creation_parses_markdown_heading_analysis(monkeypatch):
    """REGRESSION: forwarding an FP whose analysis comes back as Markdown
    headings must store a NON-EMPTY proposed_changes (empty before the fix)."""
    monkeypatch.setattr(spam_filter, "lookup_decision", lambda *a, **k: None)
    _apply_failed_events(monkeypatch)
    pending = {"conversations": []}
    _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_fp_forward_msg(), dry_run=False,
        pending=pending, analysis_text=MARKDOWN_HEADING_ANALYSIS)

    assert len(pending["conversations"]) == 1
    conv = pending["conversations"][0]
    narrow = conv["proposed_changes"]["signals_to_narrow"].get("from_analysis", "")
    assert narrow.strip() != ""


def test_e2e_yes_on_unparseable_keeps_pending_and_acks_honestly(monkeypatch):
    """REGRESSION (the exact production failure): YES on a conversation whose
    proposed_changes is empty and whose api_analysis is unparseable must:
      - NOT approve, NOT call apply_signal_changes,
      - stay awaiting_reply, log an 'apply_failed' (never 'applied') event,
      - send the honest 'Could not apply' ack."""
    monkeypatch.setattr(
        spam_filter, "apply_signal_changes",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("apply_signal_changes must NOT be called")))
    events = _apply_failed_events(monkeypatch)

    from datetime import datetime, timedelta
    sfid = "SFID-BADPARSE1"
    conv = {
        "id": sfid,
        "status": "awaiting_reply",
        "expires": (datetime.now() + timedelta(days=7)).isoformat(),
        "api_analysis": "the model wrote free prose with no readable section",
        "proposed_changes": {"signals_to_narrow": {}, "tradeoffs": ""},
        "conversation_history": [],
        "resolution": None,
    }
    pending = {"conversations": [conv]}

    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_yes_reply_msg(sfid),
        dry_run=False, pending=pending)

    assert conv["status"] == "awaiting_reply"
    assert conv["resolution"] is None
    ev_types = [e.get("event") for e in events]
    assert "applied" not in ev_types
    assert "apply_failed" in ev_types
    subjects = [s for (s, _b) in calls["send_email_args"]]
    assert any(s.startswith("Could not apply the signal change [") for s in subjects)


def test_e2e_yes_self_heals_from_api_analysis(monkeypatch):
    """A conversation stored (on the M1) with EMPTY proposed_changes but a
    perfectly good Markdown-heading api_analysis must self-heal on YES:
    re-parse, apply, approve, and send the success ack."""
    applied = {"called": False, "arg": None}

    def _fake_apply(proposed, logger):
        applied["called"] = True
        applied["arg"] = proposed
        return "narrowed the promo-keyword signal"
    monkeypatch.setattr(spam_filter, "apply_signal_changes", _fake_apply)
    events = _apply_failed_events(monkeypatch)

    from datetime import datetime, timedelta
    sfid = "SFID-SELFHEAL1"
    conv = {
        "id": sfid,
        "status": "awaiting_reply",
        "expires": (datetime.now() + timedelta(days=7)).isoformat(),
        "api_analysis": MARKDOWN_HEADING_ANALYSIS,
        "proposed_changes": {"signals_to_narrow": {}, "tradeoffs": ""},
        "conversation_history": [],
        "resolution": None,
    }
    pending = {"conversations": [conv]}

    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_yes_reply_msg(sfid),
        dry_run=False, pending=pending)

    assert applied["called"] is True
    assert applied["arg"]["signals_to_narrow"].get("from_analysis", "").strip() != ""
    assert conv["status"] == "approved"
    ev_types = [e.get("event") for e in events]
    assert "applied" in ev_types
    subjects = [s for (s, _b) in calls["send_email_args"]]
    assert any("Signal Update Applied" in s for s in subjects)


def test_e2e_yes_bare_label_still_applies(monkeypatch):
    """No regression: a well-formed bare-label proposal still applies + acks."""
    applied = {"called": False}
    monkeypatch.setattr(spam_filter, "apply_signal_changes",
                        lambda proposed, logger: applied.__setitem__("called", True)
                        or "narrowed X")
    _apply_failed_events(monkeypatch)

    from datetime import datetime, timedelta
    sfid = "SFID-GOODBARE1"
    conv = {
        "id": sfid,
        "status": "awaiting_reply",
        "expires": (datetime.now() + timedelta(days=7)).isoformat(),
        "api_analysis": BARE_LABEL_ANALYSIS,
        "proposed_changes": {"signals_to_narrow": {"from_analysis": "narrow X"},
                             "tradeoffs": "low"},
        "conversation_history": [],
        "resolution": None,
    }
    pending = {"conversations": [conv]}

    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_yes_reply_msg(sfid),
        dry_run=False, pending=pending)

    assert applied["called"] is True
    assert conv["status"] == "approved"
    subjects = [s for (s, _b) in calls["send_email_args"]]
    assert any("Signal Update Applied" in s for s in subjects)


def test_e2e_modern_branch_empty_refinement_keeps_pending(monkeypatch):
    """The modern spam_example_proposal YES branch must also verify-before-ack:
    an empty proposed_refinement must NOT call apply_ai_refinement, must stay
    pending, and must send the honest failure ack."""
    monkeypatch.setattr(
        spam_filter, "apply_ai_refinement",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("apply_ai_refinement must NOT be called")))
    events = _apply_failed_events(monkeypatch)

    from datetime import datetime, timedelta
    sfid = "SFID-EMPTYREF1"
    conv = {
        "id": sfid,
        "kind": "spam_example_proposal",
        "status": "awaiting_reply",
        "expires": (datetime.now() + timedelta(days=7)).isoformat(),
        "proposed_refinement": {},
        "conversation_history": [],
        "resolution": None,
    }
    pending = {"conversations": [conv]}

    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_yes_reply_msg(sfid),
        dry_run=False, pending=pending)

    assert conv["status"] == "awaiting_reply"
    ev_types = [e.get("event") for e in events]
    assert "applied" not in ev_types
    assert "apply_failed" in ev_types
    subjects = [s for (s, _b) in calls["send_email_args"]]
    assert any(s.startswith("Could not apply the signal change [") for s in subjects)


# ===========================================================================
# Self-loop guard: the failure ack's opening line must be an own-prefix
# ===========================================================================

def test_failure_ack_opening_line_in_own_prefixes():
    import inspect
    src = inspect.getsource(spam_filter.run_filter)
    assert "MailWarden could not apply this signal change" in src, (
        "Failure-ack opening line not present as an _own_prefixes entry — "
        "the filter would reprocess its own failure email as an SFID reply")

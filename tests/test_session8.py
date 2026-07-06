"""Session 8 — B4 reply-understanding tests."""
import inspect
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402


# ── Existing-behavior baseline (must still pass after fix) ──────────────────

def test_bare_yes():
    assert spam_filter.classify_reply("yes") == "affirmative"

def test_bare_no():
    assert spam_filter.classify_reply("no") == "negative"

def test_nope():
    assert spam_filter.classify_reply("nope") == "negative"

def test_approved():
    assert spam_filter.classify_reply("approved") == "affirmative"

def test_reject():
    assert spam_filter.classify_reply("reject") == "negative"

def test_ambiguous_follow_up():
    assert spam_filter.classify_reply("what does this affect exactly?") == "follow_up"

def test_go_ahead():
    assert spam_filter.classify_reply("go ahead") == "affirmative"

def test_looks_good():
    assert spam_filter.classify_reply("looks good") == "affirmative"


# ── Bug reproductions (FAIL before fix, PASS after) ────────────────────────

def test_noted_go_ahead():
    # Was wrongly NEGATIVE because "noted" starts with "no"
    assert spam_filter.classify_reply("noted, go ahead") == "affirmative"

def test_dont_worry_looks_fine():
    # Was wrongly NEGATIVE because text starts with "don't"
    assert spam_filter.classify_reply("don't worry, looks fine") == "follow_up"


# ── Qualified-yes cases (new return value) ──────────────────────────────────

def test_yes_but_only_for_newsletters():
    assert spam_filter.classify_reply("Yes, but only for newsletters") == "qualified_yes"

def test_yes_unless_bank():
    assert spam_filter.classify_reply("yes unless it's from my bank") == "qualified_yes"

def test_approved_except_newsletters():
    assert spam_filter.classify_reply("approved except for newsletters") == "qualified_yes"

def test_yes_as_long_as():
    assert spam_filter.classify_reply("yes as long as it's not from a contact") == "qualified_yes"

def test_go_ahead_just_for_these_senders():
    assert spam_filter.classify_reply("go ahead, just for these senders") == "qualified_yes"


# ── Required change #2: affirmative + neg-combo = qualified_yes ─────────────

def test_yes_do_not_apply_to_newsletters():
    assert spam_filter.classify_reply("yes, do not apply to newsletters") == "qualified_yes"

def test_approved_do_not_add_my_bank():
    assert spam_filter.classify_reply("approved, do not add my bank") == "qualified_yes"


# ── Qualified-yes false-positive prevention ──────────────────────────────────

def test_yes_but_yeah_do_it():
    # "do it" appears after "but" → second affirmative → plain affirmative
    assert spam_filter.classify_reply("yes, but yeah, do it") == "affirmative"

def test_yes_but_go_ahead():
    # "go ahead" after "but" → plain affirmative
    assert spam_filter.classify_reply("yes but go ahead") == "affirmative"


# ── Precedence: standalone negative beats affirmative ───────────────────────

def test_negative_beats_affirmative():
    assert spam_filter.classify_reply("yes, never mind") == "negative"


# ── Explicit negation combos: no affirmative → negative ─────────────────────

def test_dont_apply():
    assert spam_filter.classify_reply("don't apply this") == "negative"

def test_do_not_add():
    assert spam_filter.classify_reply("do not add this") == "negative"


# ── Routing: qualified_yes must not apply, must leave status awaiting_reply ──

def test_qualified_yes_no_apply_spam_example():
    conv = {
        "id": "test-conv-1",
        "status": "awaiting_reply",
        "kind": "spam_example_proposal",
        "conversation_history": [],
    }
    pending = {"conversations": [conv]}

    with patch("spam_filter.persist_pending_merge"), \
         patch("spam_filter.apply_ai_refinement") as mock_apply, \
         patch("spam_filter.send_email"):
        spam_filter._send_scope_clarification(
            conv, "yes, but only for newsletters", "spam_example_proposal",
            {}, MagicMock(), "owner@example.com", pending, "SFID-001"
        )

    assert conv["status"] == "awaiting_reply"
    mock_apply.assert_not_called()


def test_qualified_yes_no_apply_false_positive():
    conv = {
        "id": "test-conv-2",
        "status": "awaiting_reply",
        "kind": "false_positive",
        "conversation_history": [],
    }
    pending = {"conversations": [conv]}

    with patch("spam_filter.persist_pending_merge"), \
         patch("spam_filter.apply_signal_changes") as mock_sig, \
         patch("spam_filter.add_blocklist_entry_local") as mock_blk, \
         patch("spam_filter.send_email"):
        spam_filter._send_scope_clarification(
            conv, "approved, just not for my bank", "false_positive",
            {}, MagicMock(), "owner@example.com", pending, "SFID-002"
        )

    assert conv["status"] == "awaiting_reply"
    mock_sig.assert_not_called()
    mock_blk.assert_not_called()


def test_qualified_yes_sends_email_with_sfid():
    conv = {"id": "test-conv-3", "status": "awaiting_reply",
            "kind": "spam_example_proposal", "conversation_history": []}
    pending = {"conversations": [conv]}

    with patch("spam_filter.persist_pending_merge"), \
         patch("spam_filter.send_email") as mock_send:
        spam_filter._send_scope_clarification(
            conv, "yes, but only on weekdays", "spam_example_proposal",
            {}, MagicMock(), "owner@example.com", pending, "SFID-XYZ"
        )

    mock_send.assert_called_once()
    subject = mock_send.call_args[0][1]
    assert "SFID-XYZ" in subject


# ── Source assertion: dispatch must route qualified_yes before negative ───────

def test_dispatch_routes_qualified_yes_before_negative():
    src = inspect.getsource(spam_filter.run_filter)
    assert 'elif classification == "qualified_yes"' in src, \
        "Missing qualified_yes branch in run_filter dispatch"
    assert "_send_scope_clarification(" in src, \
        "_send_scope_clarification not called from run_filter"
    qy_pos = src.index('elif classification == "qualified_yes"')
    neg_pos = src.index('elif classification == "negative"')
    assert qy_pos < neg_pos, \
        "qualified_yes branch must appear before negative branch"


# ── Self-loop: clarifying email opening line must be in _own_prefixes ────────

def test_self_loop_prefix_in_own_prefixes():
    src = inspect.getsource(spam_filter.run_filter)
    assert "Your reply looks like it may include a condition:" in src, \
        "Clarifying-email opening line not in _own_prefixes — self-loop risk"


# --- NOTE 1a: doesn't / does not / didn't / did not combos ---

def test_doesnt_apply_standalone():
    # has_neg_combo=True (new pattern), has_affirmative=False → branch 3 → negative
    assert spam_filter.classify_reply("this doesn't apply to newsletters") == "negative"


def test_does_not_apply_standalone():
    # has_neg_combo=True (new pattern), has_affirmative=False → branch 3 → negative
    assert spam_filter.classify_reply("this does not apply to newsletters") == "negative"


def test_didnt_apply_standalone():
    # has_neg_combo=True (new pattern), has_affirmative=False → branch 3 → negative
    assert spam_filter.classify_reply("this didn't apply to newsletters") == "negative"


def test_did_not_apply_standalone():
    # has_neg_combo=True (new pattern), has_affirmative=False → branch 3 → negative
    assert spam_filter.classify_reply("this did not apply to newsletters") == "negative"


def test_yes_but_doesnt_apply():
    # has_neg_combo=True (new), has_affirmative=True (yes) → branch 2 → qualified_yes
    assert spam_filter.classify_reply("yes, but this doesn't apply to newsletters") == "qualified_yes"


def test_yes_doesnt_apply():
    # has_neg_combo=True (new), has_affirmative=True (yes) → branch 2 → qualified_yes
    assert spam_filter.classify_reply("yes, this doesn't apply to newsletters") == "qualified_yes"


# --- NOTE 2: broadened qualifier words ---

def test_yes_however():
    # "however" (new strong qualifier) → qualified_yes
    assert spam_filter.classify_reply("yes, however there are some exceptions") == "qualified_yes"


def test_yes_although():
    # "although" (new strong qualifier) → qualified_yes
    assert spam_filter.classify_reply("yes, although I have concerns") == "qualified_yes"


def test_yes_provided():
    # "provided" (new strong qualifier) — no "only" in string to isolate this keyword
    assert spam_filter.classify_reply("yes, provided this covers bulk mail") == "qualified_yes"


def test_yes_assuming():
    # "assuming" (new strong qualifier) — no "only" in string to isolate this keyword
    assert spam_filter.classify_reply("yes, assuming this is for bulk email") == "qualified_yes"


# --- NOTE 3: duplicate conversation_history entry ---

def test_qualified_yes_history_recorded_once():
    """_send_scope_clarification must NOT append to conversation_history.
    The dispatch at line 5925 records the user reply before calling this function."""
    conv = {
        "status": "awaiting_reply",
        "conversation_history": [],
        "last_reply_id": None,
    }
    reply_text = "yes, but this doesn't apply to newsletters"

    # Simulate what dispatch does at line 5925 before calling _send_scope_clarification
    conv["conversation_history"].append({
        "role": "user_reply",
        "timestamp": "2026-06-22T00:00:00",
        "content": reply_text,
    })

    with patch("spam_filter.send_email"), \
         patch("spam_filter.persist_pending_merge"):
        spam_filter._send_scope_clarification(
            conv,
            reply_text,
            "spam_example_proposal",
            {},
            MagicMock(),
            "user@example.com",
            {"conversations": {}},
            "sfid-test-123",
        )

    # Must be exactly 1 entry — the one added by the dispatch simulation above
    assert len(conv["conversation_history"]) == 1, (
        f"Expected 1 history entry, got {len(conv['conversation_history'])}: "
        f"{conv['conversation_history']}"
    )
    assert conv["conversation_history"][0]["role"] == "user_reply"


# ── Self-loop fix: learner proposal email must be recognizable as own mail ──

def test_learner_proposal_prefix_in_own_prefixes():
    """The learner's proposal email opening line must appear verbatim in
    _own_prefixes so the filter does not misread its own proposal as a reply.
    Pins the exact static text — fails loudly if the wording changes without
    _own_prefixes being updated to match."""
    src = inspect.getsource(spam_filter.run_filter)
    assert (
        "MailWarden analyzed the spam example you submitted and proposes a "
        "new refinement to add to the filter."
    ) in src, (
        "Learner proposal-email opening line not in _own_prefixes — self-loop risk"
    )


def test_learner_send_stamps_system_header():
    """learn_signals._send must stamp X-MailWarden-System: 1 on the message it
    sends, so the main loop's generic self-loop guard skips MailWarden's own
    proposal email before any command parsing runs."""
    import learn_signals

    captured = {}

    class _FakeServer:
        def sendmail(self, from_addr, to_addrs, msg_string):
            captured["msg_string"] = msg_string

        def quit(self):
            pass

    with patch("utils.smtp_login", return_value=_FakeServer()):
        ok = learn_signals._send(
            {"smtp": {"host": "smtp.example.com", "from_address": "bot@example.com"}},
            "owner@example.com",
            "[SFID-x] Proposed refinement — test",
            "body text",
            MagicMock(),
        )

    assert ok is True
    import email as _email
    sent = _email.message_from_string(captured["msg_string"])
    assert sent["X-MailWarden-System"] == "1"

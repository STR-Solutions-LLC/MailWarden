#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Tests for item (b) — FP-driven learned-rule review.

Covers: command grammar (KEEP/DROP) + _parse_command_numbers parity with the
eval-frozen APPROVE parser; retire_ai_refinement (reversible status flip);
the rule_reviews.json queue (enqueue dedupe / R--only / evidence cap /
dequeue); daily_report rendering + token-map parity + token-mint gate;
the run_filter KEEP/DROP reply branch end-to-end; and a HERMETICITY guard
proving the classify prompt is byte-identical whether or not this feature's
state exists (constraint #4 — zero classify-path change).
"""
import json
import logging as _logging
import os
import sys
from datetime import datetime, timedelta

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402
import daily_report  # noqa: E402
import learn_signals  # noqa: E402

_LOGGER = _logging.getLogger("test_rule_review")
_LOGGER.addHandler(_logging.NullHandler())


# ═════════════════════════════════════════════════════════════════════════
# 1. Command grammar — _parse_command_numbers parity + KEEP/DROP
# ═════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("text,expected", [
    ("APPROVE 3", [3]),
    ("APPROVE 3,5", [3, 5]),
    ("APPROVE 3 5", [3, 5]),
    ("APPROVE 3-5", [3, 4, 5]),
    ("approve 1", [1]),
    ("nope", []),
    ("", []),
])
def test_parse_approve_parity_after_refactor(text, expected):
    # parse_approve_command must remain byte-for-byte behavior after being
    # re-expressed on top of the shared _parse_command_numbers helper.
    assert spam_filter.parse_approve_command(text) == expected


@pytest.mark.parametrize("verb", ["approve", "keep", "drop", "restore"])
def test_shared_number_parser_forms(verb):
    assert spam_filter._parse_command_numbers(f"{verb} 2,4", verb) == [2, 4]
    assert spam_filter._parse_command_numbers(f"{verb} 2-4", verb) == [2, 3, 4]
    assert spam_filter._parse_command_numbers("something else", verb) == []


def test_restore_does_not_collide_with_drop():
    # "RESTORE 1" must NOT parse as a DROP (the anchored "drop" verb only
    # matches a line that STARTS with "drop").
    assert spam_filter._parse_command_numbers("RESTORE 1", "drop") == []
    assert spam_filter._parse_command_numbers("RESTORE 1", "restore") == [1]


@pytest.mark.parametrize("text,expected", [
    ("DROP 1", ("DROP", [1])),
    ("drop 2,3", ("DROP", [2, 3])),
    ("KEEP 1", ("KEEP", [1])),
    ("keep 4-6", ("KEEP", [4, 5, 6])),
    ("DROP 2\nKEEP 3", ("DROP", [2])),        # drop wins when both present
    ("RESTORE 1", ("RESTORE", [1])),
    ("restore 2,3", ("RESTORE", [2, 3])),
    ("restore 4-6", ("RESTORE", [4, 5, 6])),
    ("RESTORE 1\nDROP 2", ("RESTORE", [1])),  # restore checked first
    ("thanks!", None),
    ("", None),
])
def test_parse_rule_review_command(text, expected):
    assert spam_filter.parse_rule_review_command(text) == expected


# Finding #15 — _ignored_command_notes (DETECT-AND-TELL). Pins the exact
# owner-facing wording and proves it never fires for a single-verb reply.
_EXPECT_DROP2_NOTE = (
    "You also included DROP 2 in this reply. MailWarden handles one type of "
    "command per reply, so DROP 2 was not done. Please reply to this email "
    "with only DROP 2 and MailWarden will take care of it.")


def test_ignored_command_notes_detects_the_other_verb():
    notes = spam_filter._ignored_command_notes("KEEP 1\nDROP 2", "keep")
    assert notes == [_EXPECT_DROP2_NOTE]


def test_ignored_command_notes_empty_for_single_verb():
    assert spam_filter._ignored_command_notes("DROP 2", "drop") == []
    assert spam_filter._ignored_command_notes("APPROVE 1", "approve") == []


def test_ignored_command_notes_names_command_as_written():
    # {cmd} echoes exactly what the owner typed (verb + numbers).
    notes = spam_filter._ignored_command_notes("APPROVE 1\nRESTORE 3,5",
                                               "approve")
    assert notes == [
        "You also included RESTORE 3,5 in this reply. MailWarden handles one "
        "type of command per reply, so RESTORE 3,5 was not done. Please reply "
        "to this email with only RESTORE 3,5 and MailWarden will take care of "
        "it."]


def test_rule_review_section_never_self_triggers():
    # A quoted copy of the report's own instruction lines must NOT parse as a
    # command (the verbs only ever appear after "To " or mid-line).
    ordered = [{
        "rule_id": "R-20260703-aaaa", "headline": "H",
        "confidence": "medium", "what_this_doesnt_cover": "",
        "evidence": [{"from": "x@y.test", "subject": "s"}],
    }]
    body = "\n".join(daily_report.build_rule_review_section(ordered))
    assert spam_filter.parse_rule_review_command(body) is None


# ═════════════════════════════════════════════════════════════════════════
# 2. retire_ai_refinement — reversible status flip
# ═════════════════════════════════════════════════════════════════════════

def _signals_with_rule(rid="R-20260703-aaaa", headline="Urgent fundraising",
                       status="active"):
    return {"signals": {}, "ai_refinements": [{
        "id": rid, "headline": headline, "rationale": "r",
        "confidence": "medium",
        "what_this_doesnt_cover": "may hit real nonprofits",
        "verdict": "spam", "status": status,
    }]}


@pytest.fixture
def signals_path(tmp_path, monkeypatch):
    # spam_filter.load_signals reads spam_filter.SIGNALS_PATH; retire persists
    # via learn_signals.save_signals which writes learn_signals.SIGNALS_PATH.
    # In production these are the same file; the test must redirect BOTH.
    p = tmp_path / "signals.json"
    monkeypatch.setattr(spam_filter, "SIGNALS_PATH", p)
    monkeypatch.setattr(learn_signals, "SIGNALS_PATH", p)
    return p


def _write_signals(path, data):
    path.write_text(json.dumps(data))


def test_retire_flips_status_and_is_reversible(signals_path):
    _write_signals(signals_path, _signals_with_rule())
    assert spam_filter.retire_ai_refinement("R-20260703-aaaa", _LOGGER) is True
    data = json.loads(signals_path.read_text())
    ref = data["ai_refinements"][0]
    assert ref["status"] == "retired"       # not deleted — record preserved
    assert ref["headline"] == "Urgent fundraising"
    assert "retired_at" in ref


def test_retire_excludes_rule_from_prompt_injection(signals_path):
    _write_signals(signals_path, _signals_with_rule())
    signals = spam_filter.load_signals()
    # Present before retire.
    assert "R-20260703-aaaa" in spam_filter.injected_rule_ids(signals)
    spam_filter.retire_ai_refinement("R-20260703-aaaa", _LOGGER)
    signals_after = spam_filter.load_signals()
    assert "R-20260703-aaaa" not in spam_filter.injected_rule_ids(signals_after)


def test_retire_idempotent_on_already_retired(signals_path):
    _write_signals(signals_path, _signals_with_rule(status="retired"))
    assert spam_filter.retire_ai_refinement("R-20260703-aaaa", _LOGGER) is False


def test_retire_missing_rule_returns_false(signals_path):
    _write_signals(signals_path, _signals_with_rule())
    assert spam_filter.retire_ai_refinement("R-nope", _LOGGER) is False


# ═════════════════════════════════════════════════════════════════════════
# 2b. unretire_ai_refinement (finding #10) — reverse the DROP (status flip back)
# ═════════════════════════════════════════════════════════════════════════

def test_unretire_flips_retired_back_to_active(signals_path):
    # Full round-trip: drop (retire) then restore (unretire). The record was
    # never deleted, so restore is a pure status flip on intact data.
    _write_signals(signals_path, _signals_with_rule())
    spam_filter.retire_ai_refinement("R-20260703-aaaa", _LOGGER)  # sets retired_at
    restored = spam_filter.unretire_ai_refinement("R-20260703-aaaa", _LOGGER)
    assert restored is not None
    assert restored["headline"] == "Urgent fundraising"      # data intact
    data = json.loads(signals_path.read_text())
    ref = data["ai_refinements"][0]
    assert ref["status"] == "active"
    assert "retired_at" not in ref                            # cleared on restore
    assert "last_reinforced" in ref
    assert ref["headline"] == "Urgent fundraising"            # nothing reconstructed


def test_unretire_reactivates_rule_for_prompt_injection(signals_path):
    _write_signals(signals_path, _signals_with_rule())
    spam_filter.retire_ai_refinement("R-20260703-aaaa", _LOGGER)
    # Gone from the prompt after DROP...
    assert "R-20260703-aaaa" not in spam_filter.injected_rule_ids(
        spam_filter.load_signals())
    spam_filter.unretire_ai_refinement("R-20260703-aaaa", _LOGGER)
    # ...back in the prompt after RESTORE (fires again next sweep).
    assert "R-20260703-aaaa" in spam_filter.injected_rule_ids(
        spam_filter.load_signals())


def test_unretire_idempotent_on_active_rule(signals_path):
    # RESTORE on a rule that was never dropped => honest no-op (returns None).
    _write_signals(signals_path, _signals_with_rule())          # status active
    assert spam_filter.unretire_ai_refinement("R-20260703-aaaa", _LOGGER) is None
    assert (json.loads(signals_path.read_text())
            ["ai_refinements"][0]["status"] == "active")        # unchanged


def test_unretire_missing_rule_returns_none(signals_path):
    _write_signals(signals_path, _signals_with_rule())
    assert spam_filter.unretire_ai_refinement("R-nope", _LOGGER) is None


# ═════════════════════════════════════════════════════════════════════════
# 3. rule_reviews.json queue — enqueue / dedupe / evidence cap / dequeue
# ═════════════════════════════════════════════════════════════════════════

@pytest.fixture
def reviews_path(tmp_path, monkeypatch):
    p = tmp_path / "rule_reviews.json"
    monkeypatch.setattr(spam_filter, "RULE_REVIEWS_PATH", p)
    return p


def _ev(frm="News <n@give.test>", subject="Only hours left", account="Acct"):
    return {"from": frm, "subject": subject, "account": account}


def test_enqueue_only_r_ids(reviews_path):
    signals = _signals_with_rule()
    pairs = [("R-20260703-aaaa", _ev()), ("S-deadbeef", _ev())]
    enq = spam_filter.enqueue_rule_reviews(pairs, signals, _LOGGER)
    assert enq == ["R-20260703-aaaa"]
    store = json.loads(reviews_path.read_text())
    assert list(store.keys()) == ["R-20260703-aaaa"]
    assert store["R-20260703-aaaa"]["headline"] == "Urgent fundraising"


def test_enqueue_skips_inactive_rule(reviews_path):
    signals = _signals_with_rule(status="retired")
    enq = spam_filter.enqueue_rule_reviews(
        [("R-20260703-aaaa", _ev())], signals, _LOGGER)
    assert enq == []
    assert not reviews_path.exists() or json.loads(reviews_path.read_text()) == {}


def test_enqueue_dedupes_same_rule(reviews_path):
    signals = _signals_with_rule()
    spam_filter.enqueue_rule_reviews(
        [("R-20260703-aaaa", _ev(subject="a"))], signals, _LOGGER)
    spam_filter.enqueue_rule_reviews(
        [("R-20260703-aaaa", _ev(subject="b"))], signals, _LOGGER)
    store = json.loads(reviews_path.read_text())
    assert list(store.keys()) == ["R-20260703-aaaa"]      # one entry
    assert len(store["R-20260703-aaaa"]["evidence"]) == 2  # both evidences


def test_enqueue_caps_evidence_at_five(reviews_path):
    signals = _signals_with_rule()
    for i in range(8):
        spam_filter.enqueue_rule_reviews(
            [("R-20260703-aaaa", _ev(subject=f"s{i}"))], signals, _LOGGER)
    store = json.loads(reviews_path.read_text())
    assert len(store["R-20260703-aaaa"]["evidence"]) == 5
    # Newest kept (prepended): s7 first.
    assert store["R-20260703-aaaa"]["evidence"][0]["subject"] == "s7"


def test_dequeue_removes_entry(reviews_path):
    signals = _signals_with_rule()
    spam_filter.enqueue_rule_reviews([("R-20260703-aaaa", _ev())], signals, _LOGGER)
    assert spam_filter.dequeue_rule_review("R-20260703-aaaa", _LOGGER) is True
    assert json.loads(reviews_path.read_text()) == {}
    # Idempotent: second call is a no-op False.
    assert spam_filter.dequeue_rule_review("R-20260703-aaaa", _LOGGER) is False


# ═════════════════════════════════════════════════════════════════════════
# 4. daily_report — decisions parse, ordering, entries/body parity, token mint
# ═════════════════════════════════════════════════════════════════════════

def test_build_approval_entries_carries_rule_ids():
    decisions = {"spam_entries": [
        {"from": "News <n@give.test>", "subject": "s", "time": "07:00",
         "confidence": "0.9", "signals": "x", "account": "Acct",
         "rule_ids": ["R-20260703-aaaa"]},
    ]}
    entries = daily_report.build_approval_entries(decisions)
    assert entries["1"]["rule_ids"] == ["R-20260703-aaaa"]


def _queue(rid="R-20260703-aaaa", first="2026-07-03T08:00:00"):
    return {rid: {"rule_id": rid, "headline": "Urgent fundraising",
                  "confidence": "medium",
                  "what_this_doesnt_cover": "may hit real nonprofits",
                  "first_queued": first, "status": "pending",
                  "evidence": [_ev()]}}


def test_ordered_rule_reviews_drops_inactive():
    signals_data = _signals_with_rule(status="retired")
    assert daily_report.ordered_rule_reviews(_queue(), signals_data) == []


def test_ordered_rule_reviews_deterministic_order():
    q = {}
    q.update(_queue("R-b", first="2026-07-03T09:00:00"))
    q.update(_queue("R-a", first="2026-07-03T08:00:00"))
    signals_data = {"ai_refinements": [
        {"id": "R-a", "headline": "A", "status": "active", "confidence": "high",
         "what_this_doesnt_cover": ""},
        {"id": "R-b", "headline": "B", "status": "active", "confidence": "low",
         "what_this_doesnt_cover": ""},
    ]}
    ordered = daily_report.ordered_rule_reviews(q, signals_data)
    assert [d["rule_id"] for d in ordered] == ["R-a", "R-b"]  # by first_queued


def test_entries_and_body_numbering_agree():
    signals_data = _signals_with_rule()
    ordered = daily_report.ordered_rule_reviews(_queue(), signals_data)
    entries = daily_report.build_rule_review_entries(ordered)
    body = "\n".join(daily_report.build_rule_review_section(ordered))
    assert entries == {"1": "R-20260703-aaaa"}
    assert '1. [R-20260703-aaaa] "Urgent fundraising"' in body
    assert "Confidence when learned: medium" in body
    assert "Known blind spot: may hit real nonprofits" in body


def test_record_report_approvals_stores_rule_reviews(tmp_path, monkeypatch):
    p = tmp_path / "report_approvals.json"
    monkeypatch.setattr(daily_report, "REPORT_APPROVALS_PATH", p)
    daily_report.record_report_approvals(
        "tok", "Acct", datetime.now(), {"1": {"from_domain": "x.test"}},
        _LOGGER, rule_reviews={"1": "R-20260703-aaaa"})
    data = json.loads(p.read_text())
    assert data["tok"]["rule_reviews"] == {"1": "R-20260703-aaaa"}


def test_report_body_renders_rule_review_section():
    cfg = {"filter": {"dry_run": True},
           "accounts": [{"name": "Acct", "enabled": True,
                         "username": "o@example.com"}]}
    decisions = {"evaluated": 0, "spam_moved": 0, "spam_dry_run": 0,
                 "not_spam": 0, "errors": 0, "spam_entries": [],
                 "per_account": {"Acct": {"evaluated": 0, "spam": 0,
                                          "spam_dry_run": 0, "not_spam": 0}}}
    signals_data = _signals_with_rule()
    ordered = daily_report.ordered_rule_reviews(_queue(), signals_data)
    body = daily_report.build_report_body(
        cfg, decisions, None, 0, signals_data, rule_reviews_ordered=ordered)
    assert "LEARNED-RULE REVIEW" in body
    assert "reply DROP and the item number" in body


# ═════════════════════════════════════════════════════════════════════════
# 5. run_filter KEEP/DROP reply branch (end-to-end, all IO mocked)
# ═════════════════════════════════════════════════════════════════════════

def _mwr_msg(subject="Re: MailWarden Report — July 03 [MWR-abc123]",
             body="DROP 1", from_email="owner@example.com"):
    return {
        "message_id": "<mwr-reply-1@example.com>", "from_email": from_email,
        "from_display_name": "Owner", "subject": subject,
        "plain_text_body": body, "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }


def _token_store(token="abc123", rule_reviews=None, entries=None):
    return {token: {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": entries or {},
        "rule_reviews": rule_reviews if rule_reviews is not None
        else {"1": "R-20260703-aaaa"},
    }}


def _rr_harness(monkeypatch, *, msg_data, dry_run=False, sender_is_owner=True,
                auth_ok=True, approvals_store=None, retire_returns=True,
                dequeue_returns=True, unretire_returns=None):
    calls = {"send_email": [], "mark_uid_seen": 0, "classify_email": 0,
             "retire": [], "dequeue": [], "enqueue": [], "unretire": []}
    cfg = {
        "filter": {"dry_run": dry_run, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": "owner@example.com",
                 "from_address": "owner@example.com"},
        "summary": {"recipient_address": "owner@example.com"},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{"name": "Acct", "enabled": True,
                      "username": "owner@example.com",
                      "imap_host": "imap.example.com", "junk_folder": "Junk",
                      "folders_to_scan": ["INBOX"]}],
    }
    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_signals", lambda: {"signals": {}})
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
                        approvals_active=False,
                        whitelist_curate_active=False: "PROMPT")
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
                        lambda *a, **k: sender_is_owner)
    monkeypatch.setattr(spam_filter, "_command_auth_ok",
                        lambda *a, **k: auth_ok)
    monkeypatch.setattr(spam_filter, "_notify_unverified_command",
                        lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: dict(approvals_store or {}))
    monkeypatch.setattr(spam_filter, "load_rule_reviews_store",
                        lambda logger: {"R-20260703-aaaa": {
                            "headline": "Urgent fundraising"}})

    def _retire(rid, logger):
        calls["retire"].append(rid)
        return retire_returns
    monkeypatch.setattr(spam_filter, "retire_ai_refinement", _retire)

    def _dequeue(rid, logger):
        calls["dequeue"].append(rid)
        return dequeue_returns
    monkeypatch.setattr(spam_filter, "dequeue_rule_review", _dequeue)

    def _unretire(rid, logger):
        calls["unretire"].append(rid)
        return unretire_returns
    monkeypatch.setattr(spam_filter, "unretire_ai_refinement", _unretire)

    def _enqueue(pairs, signals, logger):
        calls["enqueue"].append(list(pairs))
        return [p[0] for p in pairs]
    monkeypatch.setattr(spam_filter, "enqueue_rule_reviews", _enqueue)

    def _send(config, subject, body, logger, to_addr=None):
        calls["send_email"].append((subject, body, to_addr))
    monkeypatch.setattr(spam_filter, "send_email", _send)

    def _seen(conn, uid, logger):
        calls["mark_uid_seen"] += 1
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    def _classify(*a, **k):
        calls["classify_email"] += 1
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
                        lambda conn, folder, logger: [b"1"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"raw")
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_data))
    spam_filter.run_filter(force=True)
    return calls


def test_drop_retires_and_dequeues(monkeypatch):
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="DROP 1"),
                        approvals_store=_token_store())
    assert calls["retire"] == ["R-20260703-aaaa"]
    assert calls["dequeue"] == ["R-20260703-aaaa"]
    assert calls["mark_uid_seen"] == 1
    assert calls["classify_email"] == 0
    subject, body, to_addr = calls["send_email"][0]
    assert body.startswith('Dropped rule 1 ("Urgent fundraising").')


def test_keep_dequeues_without_retire(monkeypatch):
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="KEEP 1"),
                        approvals_store=_token_store())
    assert calls["retire"] == []
    assert calls["dequeue"] == ["R-20260703-aaaa"]
    subject, body, to_addr = calls["send_email"][0]
    assert body == 'Kept rule 1 ("Urgent fundraising"). No change.'


def test_multi_verb_reply_runs_one_and_tells_owner_the_other(monkeypatch):
    """Finding #15: a reply stacking KEEP 1 and DROP 2 still executes exactly
    one verb (DROP wins by precedence) — KEEP is NOT run — and the ack names
    the ignored KEEP so the owner knows it was skipped and how to run it."""
    calls = _rr_harness(
        monkeypatch, msg_data=_mwr_msg(body="KEEP 1\nDROP 2"),
        approvals_store=_token_store(
            rule_reviews={"1": "R-20260703-aaaa", "2": "R-20260703-aaaa"}))
    # Only DROP executed (retire fires on DROP, never on KEEP).
    assert calls["retire"] == ["R-20260703-aaaa"]
    subject, body, to_addr = calls["send_email"][0]
    assert body.startswith('Dropped rule 2 ("Urgent fundraising").')
    assert ("You also included KEEP 1 in this reply. MailWarden handles one "
            "type of command per reply, so KEEP 1 was not done. Please reply "
            "to this email with only KEEP 1 and MailWarden will take care of "
            "it.") in body


def test_drop_invalid_number_ack(monkeypatch):
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="DROP 9"),
                        approvals_store=_token_store())
    assert calls["retire"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("Couldn't find review item 9 in that report. "
                    "No changes made.")


def test_drop_already_reviewed_replay(monkeypatch):
    # retire returns False (already retired) => idempotent "already reviewed".
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="DROP 1"),
                        approvals_store=_token_store(),
                        retire_returns=False)
    subject, body, to_addr = calls["send_email"][0]
    assert body == "Rule 1 was already reviewed — no change."


def test_dry_run_defers_keep_drop(monkeypatch):
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="DROP 1"),
                        dry_run=True, approvals_store=_token_store())
    assert calls["retire"] == []
    assert calls["dequeue"] == []
    assert calls["send_email"] == []
    assert calls["mark_uid_seen"] == 0


def test_expired_token_rejects_review(monkeypatch):
    store = _token_store()
    store["abc123"]["created"] = (datetime.now()
                                  - timedelta(days=31)).isoformat()
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="DROP 1"),
                        approvals_store=store)
    assert calls["retire"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert "too old" in body


def test_approve_rescue_enqueues_learned_rule(monkeypatch):
    # APPROVE 1 rescues a message whose entry carries an R- rule id; the
    # implicated learned rule is queued for review.
    entries = {"1": {"from_domain": "give.test",
                     "from": "News <n@give.test>", "subject": "Only hours",
                     "rule_ids": ["R-20260703-aaaa", "S-deadbeef"]}}
    store = _token_store(rule_reviews={}, entries=entries)
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 1"),
                        approvals_store=store)
    assert len(calls["enqueue"]) == 1
    pairs = calls["enqueue"][0]
    # Both ids are forwarded; enqueue_rule_reviews filters to R- internally.
    assert ("R-20260703-aaaa", {"from": "News <n@give.test>",
                                "subject": "Only hours",
                                "account": "Acct"}) in pairs


def test_approve_rescue_no_rule_ids_no_enqueue(monkeypatch):
    entries = {"1": {"from_domain": "give.test",
                     "from": "News <n@give.test>", "subject": "s"}}
    store = _token_store(rule_reviews={}, entries=entries)
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 1"),
                        approvals_store=store)
    assert calls["enqueue"] == []


# ═════════════════════════════════════════════════════════════════════════
# 5b. run_filter RESTORE reply branch (finding #10) — reverse a DROP by email
# ═════════════════════════════════════════════════════════════════════════

def test_restore_reactivates_dropped_rule(monkeypatch):
    # Owner replies RESTORE 1 to the DROP ack (same [MWR-] token). The rule is
    # un-retired and acked; mark-seen only on success; no classification.
    calls = _rr_harness(
        monkeypatch, msg_data=_mwr_msg(body="RESTORE 1"),
        approvals_store=_token_store(),
        unretire_returns={"headline": "Urgent fundraising"})
    assert calls["unretire"] == ["R-20260703-aaaa"]
    assert calls["retire"] == []
    assert calls["mark_uid_seen"] == 1
    assert calls["classify_email"] == 0
    subject, body, to_addr = calls["send_email"][0]
    assert body == ('Restored rule 1 ("Urgent fundraising"). MailWarden will '
                    "use it again starting with the next scan.")


def test_restore_on_not_dropped_rule_is_honest_noop(monkeypatch):
    # unretire returns None (rule active / already restored) => no-op ack.
    calls = _rr_harness(
        monkeypatch, msg_data=_mwr_msg(body="RESTORE 1"),
        approvals_store=_token_store(),
        unretire_returns=None)
    assert calls["unretire"] == ["R-20260703-aaaa"]
    subject, body, to_addr = calls["send_email"][0]
    assert body == "Rule 1 isn't currently dropped — no change."


def test_restore_invalid_number_ack(monkeypatch):
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="RESTORE 9"),
                        approvals_store=_token_store())
    assert calls["unretire"] == []          # never reached for an unknown number
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("Couldn't find review item 9 in that report. "
                    "No changes made.")


def test_restore_rejected_from_non_owner(monkeypatch):
    # A RESTORE from a non-owner is treated as ordinary mail (same gate as
    # APPROVE/DROP): no un-retire, no rule-review ack.
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="RESTORE 1"),
                        approvals_store=_token_store(),
                        sender_is_owner=False,
                        unretire_returns={"headline": "Urgent fundraising"})
    assert calls["unretire"] == []
    assert calls["send_email"] == []
    assert calls["classify_email"] == 1     # fell through to classification


def test_dry_run_defers_restore(monkeypatch):
    # RESTORE writes signals.json (a real side effect); Dry Run defers it just
    # like DROP — left UNSEEN, honored on the first real run.
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="RESTORE 1"),
                        dry_run=True, approvals_store=_token_store(),
                        unretire_returns={"headline": "Urgent fundraising"})
    assert calls["unretire"] == []
    assert calls["send_email"] == []
    assert calls["mark_uid_seen"] == 0


def test_drop_ack_copy_no_longer_promises_reversibility(monkeypatch):
    # Finding #10 regression: the DROP ack must NOT claim an unbounded reversal
    # ("reversible" / "want it back") and MUST name the real RESTORE command.
    calls = _rr_harness(monkeypatch, msg_data=_mwr_msg(body="DROP 1"),
                        approvals_store=_token_store())
    subject, body, to_addr = calls["send_email"][0]
    assert "reversible" not in body
    assert "want it back" not in body
    assert "RESTORE 1" in body
    assert body == ('Dropped rule 1 ("Urgent fundraising"). MailWarden will '
                    "stop applying it starting with the next scan. Changed "
                    "your mind? Reply RESTORE 1 to this email, or restore it "
                    "anytime from Dashboard -> Signal History -> Dropped "
                    "rules.")


# ═════════════════════════════════════════════════════════════════════════
# 6. HERMETICITY — classify prompt is byte-identical regardless of this feature
# ═════════════════════════════════════════════════════════════════════════

def test_classify_prompt_unaffected_by_retire_of_unrelated_rule(signals_path):
    # Two active learned rules. Retiring the FIRST must not change how the
    # SECOND renders in the classifier prompt (constraint #4: post-decision
    # plumbing only; the classify path is untouched by this feature).
    data = {"signals": {}, "ai_refinements": [
        {"id": "R-keep-me", "headline": "Keep", "rationale": "r1",
         "confidence": "high", "what_this_doesnt_cover": "",
         "verdict": "spam", "status": "active"},
        {"id": "R-drop-me", "headline": "Drop", "rationale": "r2",
         "confidence": "low", "what_this_doesnt_cover": "",
         "verdict": "spam", "status": "active"},
    ]}
    _write_signals(signals_path, data)

    # Prompt with ONLY the surviving rule present (baseline reference).
    ref_only = {"signals": {}, "ai_refinements": [data["ai_refinements"][0]]}
    _write_signals(signals_path, ref_only)
    expected = spam_filter.build_classifier_prompt(spam_filter.load_signals())

    # Now the full two-rule signals, retire the unrelated one, rebuild.
    _write_signals(signals_path, data)
    spam_filter.retire_ai_refinement("R-drop-me", _LOGGER)
    got = spam_filter.build_classifier_prompt(spam_filter.load_signals())
    assert got == expected


def test_classify_prompt_byte_identical_after_retire_then_unretire(signals_path):
    # RESTORE is a pure status flip: dropping then restoring a rule must return
    # the classifier prompt to byte-for-byte its pre-drop form (unretire adds
    # last_reinforced / clears retired_at, neither of which the prompt renders).
    data = {"signals": {}, "ai_refinements": [
        {"id": "R-keep-me", "headline": "Keep", "rationale": "r1",
         "confidence": "high", "what_this_doesnt_cover": "",
         "verdict": "spam", "status": "active"},
        {"id": "R-round-trip", "headline": "Round", "rationale": "r2",
         "confidence": "low", "what_this_doesnt_cover": "",
         "verdict": "spam", "status": "active"},
    ]}
    _write_signals(signals_path, data)
    baseline = spam_filter.build_classifier_prompt(spam_filter.load_signals())

    spam_filter.retire_ai_refinement("R-round-trip", _LOGGER)
    spam_filter.unretire_ai_refinement("R-round-trip", _LOGGER)
    got = spam_filter.build_classifier_prompt(spam_filter.load_signals())
    assert got == baseline


# ═════════════════════════════════════════════════════════════════════════
# 7. Finding #18 — mid-run DROP/RESTORE refreshes the in-memory classify
#    snapshot, so mail LATER in the SAME run no longer uses the retired rule
#    (and a restored rule is used immediately). REAL build_classifier_prompt /
#    injected_rule_ids; stateful load_signals + retire/unretire.
# ═════════════════════════════════════════════════════════════════════════

_RULE_ID = "R-20260703-aaaa"


def _active_rule_store():
    return {"signals": {}, "ai_refinements": [
        {"id": _RULE_ID, "status": "active", "verdict": "spam",
         "rule_class": "protect", "headline": "Urgent fundraising",
         "rationale": "asks for gift cards", "scope": "all"}]}


def _plain_msg():
    m = _mwr_msg(subject="Weekly newsletter from Acme",
                 body="Hello, here is our weekly update.",
                 from_email="news@acme.test")
    m["message_id"] = "<plain-2@acme.test>"
    return m


def _snapshot_harness(monkeypatch, *, store, uids, msg_map):
    """Drive run_filter (live) with REAL build_classifier_prompt /
    injected_rule_ids and a stateful signals store. retire/unretire mutate the
    store; load_signals returns a fresh deep copy each call. Captures every
    prompt build result and every system_prompt handed to classify_email."""
    import copy
    calls = {"build_results": [], "classify_prompts": [], "retire": [],
             "unretire": [], "dequeue": []}
    cfg = {
        "filter": {"dry_run": False, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": "owner@example.com",
                 "from_address": "owner@example.com"},
        "summary": {"recipient_address": "owner@example.com"},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{"name": "Acct", "enabled": True,
                      "username": "owner@example.com",
                      "imap_host": "imap.example.com", "junk_folder": "Junk",
                      "folders_to_scan": ["INBOX"]}],
    }
    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: copy.deepcopy(store))
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
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "prune_decisions_log", lambda: None)
    monkeypatch.setattr(spam_filter, "prune_pending_signals", lambda: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "migrate_fp_narrowings",
                        lambda signals, logger: False)
    monkeypatch.setattr(spam_filter, "scan_train_folder",
                        lambda conn, account, config, logger: None)
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed",
                        lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "log_decision", lambda *a, **k: None)
    # Realistic owner check: True ONLY for the owner's own address (matches
    # production). The old unconditional `True` also made the ordinary
    # non-owner message (msg 2) look like the owner, which the owner-mail
    # junking exemption (gate 0) would then exempt from classification.
    monkeypatch.setattr(
        spam_filter, "_command_sender_is_owner",
        lambda from_email, *a, **k: (from_email or "").strip().lower()
        == "owner@example.com")
    monkeypatch.setattr(spam_filter, "_command_auth_ok", lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "_notify_unverified_command",
                        lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: _token_store())
    monkeypatch.setattr(spam_filter, "load_rule_reviews_store",
                        lambda logger: {_RULE_ID: {
                            "headline": "Urgent fundraising"}})

    # REAL build_classifier_prompt, wrapped only to count/record results.
    _real_bcp = spam_filter.build_classifier_prompt

    def _bcp(signals, username=None, approvals_active=False,
             whitelist_curate_active=False):
        p = _real_bcp(signals, username, approvals_active=approvals_active,
                      whitelist_curate_active=whitelist_curate_active)
        calls["build_results"].append(p)
        return p
    monkeypatch.setattr(spam_filter, "build_classifier_prompt", _bcp)

    def _retire(rid, logger):
        calls["retire"].append(rid)
        for r in store["ai_refinements"]:
            if r["id"] == rid and r["status"] == "active":
                r["status"] = "retired"
                return True
        return False
    monkeypatch.setattr(spam_filter, "retire_ai_refinement", _retire)

    def _unretire(rid, logger):
        calls["unretire"].append(rid)
        for r in store["ai_refinements"]:
            if r["id"] == rid and r["status"] == "retired":
                r["status"] = "active"
                return r
        return None
    monkeypatch.setattr(spam_filter, "unretire_ai_refinement", _unretire)

    def _dequeue(rid, logger):
        calls["dequeue"].append(rid)
        return True
    monkeypatch.setattr(spam_filter, "dequeue_rule_review", _dequeue)
    monkeypatch.setattr(spam_filter, "enqueue_rule_reviews",
                        lambda pairs, signals, logger: [])
    monkeypatch.setattr(spam_filter, "send_email",
                        lambda config, subject, body, logger, to_addr=None: None)
    monkeypatch.setattr(spam_filter, "mark_uid_seen",
                        lambda conn, uid, logger: None)

    def _classify(client, system_prompt, *a, **k):
        calls["classify_prompts"].append(system_prompt)
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
                        lambda conn, folder, logger: list(uids))
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: uid)
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_map[raw]))
    spam_filter.run_filter(force=True)
    return calls


def test_drop_rebuilds_snapshot_excluding_dropped_rule(monkeypatch):
    # A DROP mid-run must rebuild the classify snapshot from fresh signals.
    # Old code built the prompt once (rule active) and never refreshed.
    calls = _snapshot_harness(
        monkeypatch, store=_active_rule_store(),
        uids=[b"1"], msg_map={b"1": _mwr_msg(body="DROP 1")})
    assert calls["retire"] == [_RULE_ID]
    # Two builds: the per-account build (rule active) + the post-DROP rebuild.
    assert len(calls["build_results"]) == 2
    assert _RULE_ID in calls["build_results"][0]        # initial: rule present
    assert _RULE_ID not in calls["build_results"][1]    # rebuild: rule gone


def test_dropped_rule_not_in_prompt_for_later_message_same_run(monkeypatch):
    # End-to-end: the DROP reply is message 1; message 2 (ordinary mail) must
    # be classified against a prompt that no longer carries the dropped rule.
    calls = _snapshot_harness(
        monkeypatch, store=_active_rule_store(),
        uids=[b"1", b"2"],
        msg_map={b"1": _mwr_msg(body="DROP 1"), b"2": _plain_msg()})
    assert calls["retire"] == [_RULE_ID]
    assert len(calls["classify_prompts"]) == 1          # only msg 2 is classified
    assert _RULE_ID not in calls["classify_prompts"][0]


def test_restore_rebuilds_snapshot_including_restored_rule(monkeypatch):
    # RESTORE mid-run reactivates a rule the run-start snapshot excluded; the
    # rebuild must bring it back for the rest of the run.
    store = _active_rule_store()
    store["ai_refinements"][0]["status"] = "retired"    # dropped before this run
    calls = _snapshot_harness(
        monkeypatch, store=store,
        uids=[b"1", b"2"],
        msg_map={b"1": _mwr_msg(body="RESTORE 1"), b"2": _plain_msg()})
    assert calls["unretire"] == [_RULE_ID]
    assert len(calls["classify_prompts"]) == 1
    assert _RULE_ID in calls["classify_prompts"][0]     # restored rule now used


def test_keep_does_not_rebuild_snapshot(monkeypatch):
    # KEEP only resolves the review queue (no status change) — it must NOT
    # trigger a snapshot rebuild. Guards the rules_changed gate against
    # over-refreshing.
    calls = _snapshot_harness(
        monkeypatch, store=_active_rule_store(),
        uids=[b"1"], msg_map={b"1": _mwr_msg(body="KEEP 1")})
    assert calls["retire"] == []
    assert calls["unretire"] == []
    assert calls["dequeue"] == [_RULE_ID]
    assert len(calls["build_results"]) == 1             # per-account build only

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Wave-5-D — authoring-time exception carve-outs, provenance-safe blacklist
removal, honest whitelist-upgrade copy, single-account resolution for the
Check-an-Email screen + teach warning, system-mail headers on the SMTP test
message, and the max_tokens / signal_learner engine-lockstep defaults.

All pure/deterministic — no real Anthropic call is ever made (advisor verdicts
are hand-built dicts or None, exactly as the app hands them to the pure
extractor). SMTP is mocked; no network. Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_wave5d.py -v
"""
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

from mailwarden_app import breadth_advisor  # noqa: E402
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import validators  # noqa: E402


# ===========================================================================
# D1 — exception carve-out inversion
# ===========================================================================

def test_has_exception_phrasing_positive():
    for desc in ("junk newsletters unless from REI",
                 "block coupons except from my bank",
                 "drop vendor mail but not from acme.com",
                 "toss it other than messages from HR"):
        assert breadth_advisor.has_exception_phrasing(desc) is True


def test_has_exception_phrasing_negative():
    for desc in ("political fundraising from Republican campaigns",
                 "webinar invitations from software vendors",
                 "emails from the [PSIAN] listserve",
                 ""):
        assert breadth_advisor.has_exception_phrasing(desc) is False


def test_exception_via_advisor_exception_senders_routes_to_ai():
    """Advisor named an exception sender -> refuse determinism, send the WHOLE
    rule to the AI (which can honor the carve-out), extract nothing."""
    desc = "Junk real-estate blasts, keeping anything from rei.com"
    verdict = {"reason": "ok", "broad": False, "concern": "", "suggestion": "",
               "subject_tokens": [], "sender_addresses": ["blast@realty.com"],
               "sender_domains": ["realty.com"], "exception_senders": ["rei.com"],
               "residual_text": "", "list_like": False}
    e = breadth_advisor.extract_enforcement(desc, verdict)
    assert e["enforcement"] == "ai"
    assert e["deterministic_entries"] == []
    assert e["subject_tokens"] == []
    assert e["sender_addresses"] == []
    assert e["sender_domains"] == []
    assert e["residual_text"] == desc           # full original text preserved
    assert e["has_exception"] is True
    assert "rei.com" in e["exception_senders"]


def test_exception_via_phrasing_heuristic_advisor_unavailable():
    """Advisor down (verdict None). The 'unless' phrasing alone must still route
    the rule to the AI even though a [tag] and an address are present locally."""
    desc = 'Junk "[DEALS]" mail from noreply@shop.com unless it is from rei.com'
    e = breadth_advisor.extract_enforcement(desc, None)
    assert e["enforcement"] == "ai"
    assert e["deterministic_entries"] == []
    assert e["residual_text"] == desc
    assert e["has_exception"] is True
    assert e["source"] == "local"               # advisor was unavailable


def test_non_exception_rule_unchanged_deterministic():
    """A rule with no carve-out is classified exactly as before D1."""
    verdict = {"reason": "ok", "broad": False, "concern": "", "suggestion": "",
               "subject_tokens": ["[PSIAN]"], "sender_addresses": [],
               "sender_domains": [], "exception_senders": [],
               "residual_text": "", "list_like": False}
    e = breadth_advisor.extract_enforcement(
        "Emails from the [PSIAN] listserve.", verdict)
    assert e["enforcement"] == "deterministic"
    assert e["deterministic_entries"] == [
        {"kind": "subject_keyword", "value": "[psian]"}]
    assert e["has_exception"] is False
    assert e["exception_senders"] == []


def test_non_exception_rule_unchanged_no_markers_ai():
    """No markers, no carve-out -> plain 'ai' with the two new keys present."""
    verdict = {"reason": "ok", "subject_tokens": [], "sender_addresses": [],
               "sender_domains": [], "exception_senders": [],
               "residual_text": "fundraising", "list_like": False}
    e = breadth_advisor.extract_enforcement("fundraising", verdict)
    assert e["enforcement"] == "ai"
    assert e["has_exception"] is False
    assert e["exception_senders"] == []


# ---- _presave_disclosure (pure) ----

def test_presave_disclosure_no_deterministic_entries():
    should, msg = dashboard.UnwantedCategoriesTab._presave_disclosure(
        {"enforcement": "ai", "deterministic_entries": []})
    assert should is False
    assert msg == ""


def test_presave_disclosure_lists_senders_and_tokens():
    enforcement = {"enforcement": "deterministic", "deterministic_entries": [
        {"kind": "address", "value": "blast@realty.com"},
        {"kind": "domain", "value": "realty.com"},
        {"kind": "subject_keyword", "value": "[deals]"}]}
    should, msg = dashboard.UnwantedCategoriesTab._presave_disclosure(enforcement)
    assert should is True
    # Plain-language, names the outright blocks so the owner sees them first.
    assert "blast@realty.com" in msg
    assert "realty.com" in msg
    assert "[deals]" in msg
    assert "Junk" in msg


def test_presave_disclosure_handles_none():
    should, msg = dashboard.UnwantedCategoriesTab._presave_disclosure(None)
    assert should is False
    assert msg == ""


# ===========================================================================
# D2 — provenance-aware blacklist removal
# ===========================================================================

def test_blacklist_remove_decision_rule_managed_list_provenance():
    entry = {"value": "realty.com", "scope": "all", "provenance": [{"rule_id": "r1"}]}
    assert dashboard.ListsTab._blacklist_remove_decision(entry) == "rule_managed"


def test_blacklist_remove_decision_rule_managed_legacy_string():
    entry = {"value": "realty.com", "provenance": "rule-123"}
    assert dashboard.ListsTab._blacklist_remove_decision(entry) == "rule_managed"


def test_blacklist_remove_decision_delete_typed_and_approve():
    assert dashboard.ListsTab._blacklist_remove_decision("plain@typed.com") == "delete"
    assert dashboard.ListsTab._blacklist_remove_decision(
        {"value": "x@y.com", "scope": "all"}) == "delete"
    assert dashboard.ListsTab._blacklist_remove_decision(
        {"value": "a@b.com", "provenance": "approve"}) == "delete"


# ===========================================================================
# D4/D5 — single-account resolution
# ===========================================================================

def test_single_account_name_exactly_one():
    cfg = {"accounts": [{"username": "matt@example.com", "password": "x"}]}
    assert dashboard.CheckEmailTab._single_account_name(cfg) == "matt@example.com"


def test_single_account_name_zero_or_multiple():
    assert dashboard.CheckEmailTab._single_account_name({"accounts": []}) is None
    assert dashboard.CheckEmailTab._single_account_name({}) is None
    assert dashboard.CheckEmailTab._single_account_name(None) is None
    multi = {"accounts": [{"username": "a@x.com"}, {"username": "b@y.com"}]}
    assert dashboard.CheckEmailTab._single_account_name(multi) is None


def test_single_account_name_ignores_blank_username():
    cfg = {"accounts": [{"username": ""}, {"username": "real@x.com"}]}
    assert dashboard.CheckEmailTab._single_account_name(cfg) == "real@x.com"


# ===========================================================================
# D6 — system-mail headers on the SMTP test message
# ===========================================================================

class _FakeSMTP:
    def __init__(self):
        self.sent = None

    def send_message(self, msg):
        self.sent = msg

    def quit(self):
        pass


def test_send_test_email_stamps_system_headers(monkeypatch):
    fake = _FakeSMTP()
    monkeypatch.setattr(validators, "safe_smtp_connect",
                        lambda *a, **k: fake)
    ok, _msg = validators.send_test_email(
        "smtp.example.com", 587, "user", "pass",
        "sender@example.com", "to@example.org")
    assert ok is True
    sent = fake.sent
    assert sent is not None
    assert sent["X-MailWarden-System"] == "1"
    assert sent["Date"]                      # a real RFC-2822 date string
    mid = sent["Message-ID"]
    assert mid and mid.startswith("<") and mid.endswith(">")
    # Message-ID domain is taken from the From address.
    assert "example.com>" in mid


def test_send_test_email_no_domain_from_addr(monkeypatch):
    """A From with no '@' must not crash Message-ID generation."""
    fake = _FakeSMTP()
    monkeypatch.setattr(validators, "safe_smtp_connect",
                        lambda *a, **k: fake)
    ok, _ = validators.send_test_email(
        "smtp.example.com", 587, "user", "pass", "sender", "to@example.org")
    assert ok is True
    assert fake.sent["Message-ID"]           # generated with a default domain


# ===========================================================================
# D7 — engine-lockstep defaults
# ===========================================================================

def test_default_config_anthropic_max_tokens():
    # Matches spam_filter run_filter fallback: api_config.get("max_tokens", 500).
    assert config_io.DEFAULT_CONFIG["anthropic"]["max_tokens"] == 500


def test_default_config_signal_learner_examples_folder():
    # Matches learn_signals fallback: learner_cfg.get("examples_folder",
    # "spam_examples").
    assert config_io.DEFAULT_CONFIG["signal_learner"] == {
        "examples_folder": "spam_examples"}

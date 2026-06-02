#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Unit tests for the calibration + security build (run with the test venv):

  tests/.venv/bin/python -c "import pytest; raise SystemExit(pytest.main(['tests/test_fixes.py','-v']))"

Covers the deterministic fixes:
  F1 — X-Spam-Score ×10 misread (utils.check_spam_score)
  F2 — soft-signal-only stacks must NOT auto-junk (utils.check_header_signals)
  F4 — whitelist subdomain matching (spam_filter.check_whitelist)
  C1 — confidence clamp
  S1 — command sender must equal account owner
  S2 — SFID approval sender must equal account owner
(F3 / per-account scoping are validated by the corpus runner / scoping tests.)
"""
import sys
import os

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

# The desktop app lives in app/mailwarden_app and is imported as a package
# (its modules use `from . import paths`). Add app/ to the path so the
# per-account scoping helpers in config_io / dashboard can be unit-tested.
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import utils  # noqa: E402
import spam_filter  # noqa: E402
import learn_signals  # noqa: E402
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402


# ---------------------------------------------------------------------------
# F1 — X-Spam-Score is the SpamAssassin score ×10; stop reading it. Use the
# real decimal in X-Spam-Status (score=N.N) and the X-Spam-Flag / verdict.
# Only a genuinely HIGH verdict (Flag YES, verdict Yes, or decimal >= 5.0)
# is spam evidence; the normal low range must NOT fire.
# ---------------------------------------------------------------------------

def test_f1_x10_integer_ignored_instagram():
    # Instagram: real 1.6 (clean), X-Spam-Score header is 16 (=1.6x10).
    h = {"X-Spam-Status": "No, score=1.6", "X-Spam-Score": "16", "X-Spam-Flag": "NO"}
    assert utils.check_spam_score(h)["signal"] is None


def test_f1_x10_integer_ignored_dashlane():
    # Dashlane: real 0.3, X-Spam-Score header is 3 (=0.3x10). Must NOT fire.
    h = {"X-Spam-Status": "No, score=0.3", "X-Spam-Score": "3", "X-Spam-Flag": "NO"}
    assert utils.check_spam_score(h)["signal"] is None


def test_f1_flag_yes_fires():
    assert utils.check_spam_score({"X-Spam-Flag": "YES"})["signal"] == "ELEVATED_SPAM_SCORE"


def test_f1_status_verdict_yes_fires():
    assert utils.check_spam_score(
        {"X-Spam-Status": "Yes, score=7.2"})["signal"] == "ELEVATED_SPAM_SCORE"


def test_f1_status_high_decimal_fires():
    # >= 5.0 real score is genuine spam evidence (covers tag-only configs).
    assert utils.check_spam_score(
        {"X-Spam-Status": "No, score=5.1"})["signal"] == "ELEVATED_SPAM_SCORE"


def test_f1_status_below_5_no_signal():
    assert utils.check_spam_score({"X-Spam-Status": "No, score=4.9"})["signal"] is None


def test_f1_no_spam_headers_no_signal():
    # AOL/Yahoo do not stamp X-Spam-* at all.
    assert utils.check_spam_score({})["signal"] is None


# ---------------------------------------------------------------------------
# F2 — only HARD signals may auto-junk. A stack of >=3 soft signals must route
# to the AI (verdict None), never auto-junk.
# ---------------------------------------------------------------------------

def _three_soft_headers():
    return {
        "From": "alice@example.com",
        "Reply-To": "bob@unrelated.org",        # REPLY_TO_MISMATCH (soft)
        "Message-ID": "<abc@other-domain.net>",  # MESSAGE_ID_MISMATCH (soft)
    }


def test_f2_three_soft_does_not_autojunk():
    # empty body -> DEGRADED_PLAIN_TEXT (the 3rd soft signal)
    res = utils.check_header_signals(_three_soft_headers(), "")
    assert len(res["soft_signals"]) >= 3
    assert res["pre_classifier_verdict"] is None


def test_f2_hard_signal_still_autojunks():
    h = {"Authentication-Results": "spf=fail dkim=fail"}
    body = "This is a normal plain text body, long enough to avoid degraded. " * 3
    res = utils.check_header_signals(h, body)
    assert "SPF_DKIM_BOTH_FAIL" in res["hard_signals"]
    assert res["pre_classifier_verdict"] == "SPAM"


# ---------------------------------------------------------------------------
# F3 — authentication summary feeds the AI the SPF/DKIM/DMARC results and the
# cryptographically authenticated sending domain, so it can judge auth-vs-brand
# alignment (legit when the authenticated domain matches the claimed brand;
# phishing when it does not, even if DKIM/DMARC pass).
# ---------------------------------------------------------------------------

WM_AR = ("mta.yahoo.com; "
         "dkim=pass header.i=@advocacy.example.org header.s=ak01 arc_overridden_status=NOT_OVERRIDDEN; "
         "dkim=pass header.i=@wawd.fbl.e.sparkpostmail.com header.s=scph0125; "
         "spf=pass smtp.mailfrom=bounces.list.advocacy.example.org; "
         "dmarc=pass(p=NONE) header.from=advocacy.example.org")

MCAFEE_AR = ("mta.yahoo.com; "
             "dkim=pass header.i=@throwaway.example header.s=h1; "
             "spf=none smtp.mailfrom=mail-update-support.throwaway.example; "
             "dmarc=pass(p=REJECT) header.from=throwaway.example")

NBC_ARC = ("i=1; mx.microsoft.com 1; spf=pass smtp.mailfrom=corp.example.com; "
           "dmarc=pass action=none header.from=corp.example.com; "
           "dkim=pass header.d=corp.example.com; arc=none")


def test_f3_auth_womensmarch_brand_aligned():
    s = utils.summarize_authentication({"Authentication-Results": WM_AR}, "advocacy.example.org")
    assert s["spf"] == "pass"
    assert s["dkim"] == "pass"
    assert s["dmarc"] == "pass"
    assert "advocacy.example.org" in s["authenticated_domains"]


def test_f3_auth_mcafee_brand_mismatch():
    s = utils.summarize_authentication({"Authentication-Results": MCAFEE_AR}, "throwaway.example")
    assert s["spf"] == "none"
    assert s["dkim"] == "pass"          # signed by the throwaway domain...
    assert s["dmarc"] == "pass"
    assert "throwaway.example" in s["authenticated_domains"]
    assert "mcafee.com" not in s["authenticated_domains"]   # ...NOT the brand it claims


def test_f3_auth_nbcuni_via_arc_header():
    # Office365 puts the verified result in ARC-Authentication-Results.
    s = utils.summarize_authentication({"ARC-Authentication-Results": NBC_ARC}, "corp.example.com")
    assert s["spf"] == "pass"
    assert s["dkim"] == "pass"
    assert s["dmarc"] == "pass"
    assert "corp.example.com" in s["authenticated_domains"]


def test_f3_auth_absent_is_none():
    s = utils.summarize_authentication({}, "example.com")
    assert s["spf"] == "none"
    assert s["dkim"] == "none"
    assert s["dmarc"] == "none"
    assert s["authenticated_domains"] == []


# --- generality: must work for ANY provider, not just the owner's hosts ---

GMAIL_AR = ("mx.google.com; dkim=pass header.i=@example.com header.s=sel header.b=AbCdEf; "
            "spf=pass (google.com: domain of bounce@example.com designates 1.2.3.4 as "
            "permitted sender) smtp.mailfrom=bounce@example.com; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com")

OUTLOOK_AR = ("spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=contoso.com; "
              "dkim=pass (signature was verified) header.d=contoso.com; "
              "dmarc=pass action=none header.from=contoso.com")


def test_f3_auth_generic_gmail_format():
    s = utils.summarize_authentication({"Authentication-Results": GMAIL_AR}, "example.com")
    assert s["spf"] == "pass" and s["dkim"] == "pass" and s["dmarc"] == "pass"
    assert "example.com" in s["authenticated_domains"]


def test_f3_auth_generic_outlook_format():
    s = utils.summarize_authentication({"Authentication-Results": OUTLOOK_AR}, "contoso.com")
    assert s["spf"] == "pass" and s["dkim"] == "pass" and s["dmarc"] == "pass"
    assert "contoso.com" in s["authenticated_domains"]


def test_f3_unverified_dkim_signature_not_trusted():
    # A bare DKIM-Signature claim with NO Authentication-Results must NOT be
    # treated as authenticated — any sender can write any d= they like.
    s = utils.summarize_authentication(
        {"DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=spammer.com; s=x; b=AAAA"},
        "spammer.com")
    assert s["dkim"] == "none"
    assert s["claimed_dkim_domain"] == "spammer.com"
    assert "spammer.com" not in s["authenticated_domains"]


# ---------------------------------------------------------------------------
# F4 — whitelist subdomain matching (spam_filter.check_whitelist)
# ---------------------------------------------------------------------------

def _wl(domains):
    return {"_addresses_set": set(),
            "_domains_set": {d.lower().lstrip("@") for d in domains}}


def test_f4_subdomain_matches_whitelisted_domain():
    wl = _wl(["instagram.com"])
    assert spam_filter.check_whitelist("Instagram <security@mail.instagram.com>", wl)


def test_f4_exact_domain_still_matches():
    wl = _wl(["instagram.com"])
    assert spam_filter.check_whitelist("x@instagram.com", wl)


def test_f4_lookalike_domain_does_not_match():
    wl = _wl(["instagram.com"])
    assert spam_filter.check_whitelist("x@evilinstagram.com", wl) is None
    assert spam_filter.check_whitelist("x@instagram.com.evil.com", wl) is None


# ---------------------------------------------------------------------------
# C1 — clamp confidence into [0.0, 1.0]
# ---------------------------------------------------------------------------

def test_c1_clamp_above_one():
    assert spam_filter.clamp_confidence(1.5) == 1.0


def test_c1_clamp_below_zero():
    assert spam_filter.clamp_confidence(-0.2) == 0.0


def test_c1_clamp_in_range():
    assert spam_filter.clamp_confidence(0.9) == 0.9


def test_c1_clamp_numeric_string():
    assert spam_filter.clamp_confidence("0.5") == 0.5


def test_c1_clamp_malformed_is_zero():
    assert spam_filter.clamp_confidence(None) == 0.0
    assert spam_filter.clamp_confidence("xyz") == 0.0


# ---------------------------------------------------------------------------
# S1 / S2 — Whitelist/Blacklist commands and [SFID-...] approvals are honored
# ONLY from the account owner's own address.
# ---------------------------------------------------------------------------

def test_s1s2_owner_match():
    assert spam_filter._command_sender_is_owner(
        "owner@example.com", {"username": "owner@example.com"}) is True


def test_s1s2_owner_case_insensitive():
    assert spam_filter._command_sender_is_owner(
        "Owner@Example.com", {"username": "owner@example.com"}) is True


def test_s1s2_non_owner_rejected():
    assert spam_filter._command_sender_is_owner(
        "attacker@evil.com", {"username": "owner@example.com"}) is False


def test_s1s2_empty_owner_rejected():
    assert spam_filter._command_sender_is_owner("x@y.com", {"username": ""}) is False


def test_s1s2_empty_sender_rejected():
    assert spam_filter._command_sender_is_owner(
        "", {"username": "owner@example.com"}) is False


# ---------------------------------------------------------------------------
# P1 — per-account learned-rule scoping (build_classifier_prompt)
# ---------------------------------------------------------------------------

def _signals_with_refinement(scope):
    r = {"headline": "kill national-committee fundraising",
         "rationale": "user taught this", "status": "active"}
    if scope is not None:
        r["scope"] = scope
    return {"signals": {}, "ai_refinements": [r]}


HEADLINE = "kill national-committee fundraising"


def test_p1_scoped_refinement_applies_to_its_account():
    s = _signals_with_refinement(["commerce@example.com"])
    assert HEADLINE in spam_filter.build_classifier_prompt(s, "commerce@example.com")


def test_p1_scoped_refinement_excluded_from_other_account():
    s = _signals_with_refinement(["commerce@example.com"])
    assert HEADLINE not in spam_filter.build_classifier_prompt(s, "other@example.net")


def test_p1_unscoped_refinement_applies_everywhere_migration():
    s = _signals_with_refinement(None)  # legacy rule, no scope -> treated as "all"
    assert HEADLINE in spam_filter.build_classifier_prompt(s, "other@example.net")


def test_p1_all_scope_applies_everywhere():
    s = _signals_with_refinement("all")
    assert HEADLINE in spam_filter.build_classifier_prompt(s, "other@example.net")


def test_p1_no_account_includes_everything():
    s = _signals_with_refinement(["commerce@example.com"])
    assert HEADLINE in spam_filter.build_classifier_prompt(s)  # no account -> no filtering


# ---------------------------------------------------------------------------
# P1 (continued) — scope CAPTURE at creation time. learn_signals.handle_new_pattern
# must stamp the new refinement's scope from the example's forwarder so a rule
# taught by forwarding from one inbox is, from the moment it is proposed, bound
# to that inbox. A forwarder-less example cannot be account-scoped -> "all".
# ---------------------------------------------------------------------------

import logging as _logging  # noqa: E402

_QUIET_LOGGER = _logging.getLogger("test_p1_scope")
_QUIET_LOGGER.addHandler(_logging.NullHandler())


def _run_handle_new_pattern(monkeypatch, forwarder):
    """Drive learn_signals.handle_new_pattern with all IO stubbed out and
    return the proposed_refinement dict that got written to pending_signals."""
    captured = {}

    def _fake_save_pending(data):
        captured["pending"] = data

    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": []})
    monkeypatch.setattr(learn_signals, "save_pending_signals", _fake_save_pending)
    monkeypatch.setattr(learn_signals, "append_refinement_log", lambda event: None)
    monkeypatch.setattr(learn_signals, "_send",
                        lambda *a, **k: True)

    classification = {
        "kind": "new_pattern",
        "headline": "kill timeshare solicitations",
        "rationale": "user taught this",
        "what_this_doesnt_cover": "real travel confirmations",
        "confidence": "medium",
    }
    example = {
        "filename": "user-submitted-1.eml",
        "from": "promo@example.net",
        "subject": "Your resort getaway awaits",
        "forwarder": forwarder,
    }
    signals_data = {"signals": {}, "ai_refinements": []}
    config = {"accounts": [{"username": "owner@example.com"}],
              "smtp": {"host": "smtp.example.com", "username": "owner@example.com"}}

    ok = learn_signals.handle_new_pattern(
        classification, example, signals_data, config, _QUIET_LOGGER)
    assert ok is True
    conv = captured["pending"]["conversations"][-1]
    return conv["proposed_refinement"]


def test_p1_handle_new_pattern_scopes_to_forwarder(monkeypatch):
    ref = _run_handle_new_pattern(monkeypatch, "owner@example.com")
    assert ref["scope"] == ["owner@example.com"]


def test_p1_handle_new_pattern_uppercase_forwarder_is_lowercased(monkeypatch):
    ref = _run_handle_new_pattern(monkeypatch, "Owner@Example.com")
    assert ref["scope"] == ["owner@example.com"]


def test_p1_handle_new_pattern_empty_forwarder_is_all(monkeypatch):
    ref = _run_handle_new_pattern(monkeypatch, "")
    assert ref["scope"] == "all"


def test_p1_handle_new_pattern_missing_forwarder_is_all(monkeypatch):
    captured = {}
    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": []})
    monkeypatch.setattr(learn_signals, "save_pending_signals",
                        lambda data: captured.update(pending=data))
    monkeypatch.setattr(learn_signals, "append_refinement_log", lambda event: None)
    monkeypatch.setattr(learn_signals, "_send", lambda *a, **k: True)
    classification = {"kind": "new_pattern", "headline": "h", "rationale": "r"}
    example = {"filename": "x.eml", "from": "a@example.net", "subject": "s"}  # no forwarder key
    learn_signals.handle_new_pattern(
        classification, example, {"signals": {}, "ai_refinements": []},
        {"accounts": [], "smtp": {"host": "h", "username": "owner@example.com"}},
        _QUIET_LOGGER)
    ref = captured["pending"]["conversations"][-1]["proposed_refinement"]
    assert ref["scope"] == "all"


# ---------------------------------------------------------------------------
# P1 (continued) — scope must SURVIVE persistence. apply_ai_refinement copies
# the proposed refinement into signals.json[ai_refinements]; that copy must keep
# the scope it was created with (apply_ai_refinement does record = dict(...)).
# ---------------------------------------------------------------------------

def _capture_apply_ai_refinement(monkeypatch, refinement):
    """Call spam_filter.apply_ai_refinement with signals IO stubbed and return
    the ai_refinements record that was persisted."""
    saved = {}
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(spam_filter, "save_signals",
                        lambda data: saved.update(data=data))
    monkeypatch.setattr(spam_filter, "append_refinement_log", lambda event: None)
    spam_filter.apply_ai_refinement(refinement, _QUIET_LOGGER,
                                    source="email", sfid="SFID-test")
    return saved["data"]["ai_refinements"][-1]


def test_p1_scope_survives_apply_ai_refinement_list(monkeypatch):
    refinement = {"id": "R-1", "headline": "h", "rationale": "r",
                  "scope": ["x@example.net"]}
    record = _capture_apply_ai_refinement(monkeypatch, refinement)
    assert record["scope"] == ["x@example.net"]


def test_p1_scope_survives_apply_ai_refinement_all(monkeypatch):
    refinement = {"id": "R-2", "headline": "h", "rationale": "r", "scope": "all"}
    record = _capture_apply_ai_refinement(monkeypatch, refinement)
    assert record["scope"] == "all"


# ---------------------------------------------------------------------------
# P1 (continued) — APPROVAL BACKSTOP. Proposals created before scope-capture
# existed have no scope on their refinement. When such a proposal is approved
# (here via config_io.apply_refinement_from_pending — the path both Dashboard
# approve buttons delegate to), the conversation's forwarder must be carried
# into scope so the rule still binds to the inbox that taught it. If the
# refinement already carries a scope, the backstop must NOT overwrite it.
# ---------------------------------------------------------------------------

def _capture_apply_from_pending(monkeypatch, refinement, forwarder):
    """Drive config_io.apply_refinement_from_pending with all IO stubbed and
    return the ai_refinements record that was persisted to signals.json."""
    conv = {
        "id": "SFID-20260601-001",
        "kind": "spam_example_proposal",
        "status": "awaiting_reply",
        "forwarder": forwarder,
        "proposed_refinement": refinement,
    }
    saved = {}
    monkeypatch.setattr(config_io, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": [conv]})
    monkeypatch.setattr(config_io, "save_pending_signals", lambda data: None)
    monkeypatch.setattr(config_io, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(config_io, "save_signals",
                        lambda data: saved.update(data=data))
    monkeypatch.setattr(config_io, "append_refinement_log", lambda event: None)
    applied = config_io.apply_refinement_from_pending(conv["id"], source="dashboard")
    assert applied is not None
    return saved["data"]["ai_refinements"][-1]


def test_p1_backstop_carries_forwarder_into_missing_scope(monkeypatch):
    refinement = {"id": "R-old", "headline": "h", "rationale": "r"}  # no scope (legacy)
    record = _capture_apply_from_pending(monkeypatch, refinement, "x@example.net")
    assert record["scope"] == ["x@example.net"]


def test_p1_backstop_lowercases_forwarder(monkeypatch):
    refinement = {"id": "R-old2", "headline": "h", "rationale": "r"}
    record = _capture_apply_from_pending(monkeypatch, refinement, "X@Example.NET")
    assert record["scope"] == ["x@example.net"]


def test_p1_backstop_does_not_overwrite_existing_scope(monkeypatch):
    refinement = {"id": "R-new", "headline": "h", "rationale": "r",
                  "scope": ["a@example.com"]}
    record = _capture_apply_from_pending(monkeypatch, refinement, "x@example.net")
    assert record["scope"] == ["a@example.com"]


def test_p1_backstop_no_forwarder_leaves_scope_absent(monkeypatch):
    refinement = {"id": "R-old3", "headline": "h", "rationale": "r"}  # no scope
    record = _capture_apply_from_pending(monkeypatch, refinement, "")
    assert "scope" not in record  # absent -> treated as "all" by _refinement_in_scope


# ---------------------------------------------------------------------------
# P1 (continued) — pure DASHBOARD serialization helper. The per-account toggle
# row computes the scope to persist:
#   ALL configured accounts ON  -> "all"
#   a SUBSET ON                 -> list of those usernames (lowercased)
#   NONE ON                     -> []  (rule applies to no account)
# Extracted as a pure function so the GUI stays thin and this can be tested
# headlessly. Mirrors the read side in spam_filter._refinement_in_scope.
# ---------------------------------------------------------------------------

def test_p1_scope_from_toggles_all_on_is_all():
    accounts = ["a@example.com", "b@example.net"]
    assert dashboard.scope_from_toggle_state(accounts, accounts) == "all"


def test_p1_scope_from_toggles_subset_is_list():
    accounts = ["a@example.com", "b@example.net", "c@example.org"]
    assert dashboard.scope_from_toggle_state(
        accounts, ["a@example.com", "c@example.org"]) == ["a@example.com", "c@example.org"]


def test_p1_scope_from_toggles_none_on_is_empty_list():
    accounts = ["a@example.com", "b@example.net"]
    assert dashboard.scope_from_toggle_state(accounts, []) == []


def test_p1_scope_from_toggles_lowercases():
    accounts = ["A@Example.com", "B@Example.net"]
    # only the first toggled on, given in mixed case
    assert dashboard.scope_from_toggle_state(accounts, ["A@Example.com"]) == ["a@example.com"]


def test_p1_scope_from_toggles_single_account_on_is_all():
    accounts = ["solo@example.com"]
    assert dashboard.scope_from_toggle_state(accounts, ["solo@example.com"]) == "all"


# --- inverse helper: which accounts should render ON for a given scope ---

def test_p1_accounts_on_all_scope_all_on():
    accounts = ["a@example.com", "b@example.net"]
    assert set(dashboard.accounts_on_for_scope("all", accounts)) == set(accounts)


def test_p1_accounts_on_missing_scope_all_on():
    accounts = ["a@example.com", "b@example.net"]
    assert set(dashboard.accounts_on_for_scope(None, accounts)) == set(accounts)


def test_p1_accounts_on_list_scope_subset_on():
    accounts = ["a@example.com", "b@example.net", "c@example.org"]
    assert set(dashboard.accounts_on_for_scope(
        ["a@example.com", "C@Example.org"], accounts)) == {"a@example.com", "c@example.org"}


def test_p1_accounts_on_empty_scope_none_on():
    accounts = ["a@example.com", "b@example.net"]
    assert dashboard.accounts_on_for_scope([], accounts) == []


def test_p1_toggle_roundtrip_is_stable():
    # all-on -> "all" -> all-on ; subset -> list -> same subset
    accounts = ["a@example.com", "b@example.net", "c@example.org"]
    scope_all = dashboard.scope_from_toggle_state(accounts, accounts)
    assert set(dashboard.accounts_on_for_scope(scope_all, accounts)) == set(accounts)
    subset = ["a@example.com", "c@example.org"]
    scope_sub = dashboard.scope_from_toggle_state(accounts, subset)
    assert set(dashboard.accounts_on_for_scope(scope_sub, accounts)) == set(subset)


# --- persistence: config_io.set_refinement_scope writes scope to signals.json ---

def test_p1_set_refinement_scope_persists(monkeypatch):
    data = {"signals": {}, "ai_refinements": [
        {"id": "R-1", "headline": "h1"},
        {"id": "R-2", "headline": "h2", "scope": "all"},
    ]}
    saved = {}
    monkeypatch.setattr(config_io, "load_signals", lambda: data)
    monkeypatch.setattr(config_io, "save_signals", lambda d: saved.update(d=d))
    ok = config_io.set_refinement_scope("R-2", ["x@example.net"])
    assert ok is True
    target = next(r for r in saved["d"]["ai_refinements"] if r["id"] == "R-2")
    assert target["scope"] == ["x@example.net"]


def test_p1_set_refinement_scope_missing_id_returns_false(monkeypatch):
    monkeypatch.setattr(config_io, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(config_io, "save_signals",
                        lambda d: (_ for _ in ()).throw(AssertionError("should not save")))
    assert config_io.set_refinement_scope("nope", "all") is False

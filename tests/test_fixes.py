#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Unit tests for the calibration + security build (run with the test venv):

  tests/.venv/bin/python -c "import pytest; raise SystemExit(pytest.main(['tests/test_fixes.py','-v']))"

Covers the deterministic fixes:
  F1 — X-Spam-Score ×10 misread (utils.check_spam_score / utils.host_spam_verdict)
  F2 — only HARD signals auto-junk; soft signals removed (utils.check_header_signals)
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


# host_spam_verdict — present-only summary built on the SAME ×10-safe parsing.

def test_f1_host_verdict_absent_is_none():
    # No X-Spam-* header at all -> None (caller omits the line entirely).
    assert utils.host_spam_verdict({}) is None


def test_f1_host_verdict_x10_uses_real_decimal_not_times_ten():
    # Instagram: real 1.6, header X-Spam-Score=16. Must report score=1.6, flag no.
    v = utils.host_spam_verdict(
        {"X-Spam-Status": "No, score=1.6", "X-Spam-Score": "16", "X-Spam-Flag": "NO"})
    assert v == {"score": 1.6, "flag": "no", "verdict": "no"}


def test_f1_host_verdict_high_flag_is_yes():
    assert utils.host_spam_verdict({"X-Spam-Flag": "YES"}) == \
        {"score": None, "flag": "yes", "verdict": "yes"}


def test_f1_host_verdict_present_low_flag_is_no():
    # Present but clean -> a factual no/score line is still emitted by the caller.
    assert utils.host_spam_verdict({"X-Spam-Flag": "NO"}) == \
        {"score": None, "flag": "no", "verdict": "no"}


# ---------------------------------------------------------------------------
# F2 — only HARD signals may auto-junk. Soft signals were removed entirely:
# check_header_signals now always returns soft_signals == [], and any message
# without a HARD signal routes to the AI (verdict None), never auto-junked.
# ---------------------------------------------------------------------------

def _non_hard_headers():
    # Reply-To / Message-ID domain mismatches + empty body used to manufacture
    # 3 SOFT signals. None of those are signals anymore, so this message must
    # produce NO signals at all and route to the AI.
    return {
        "From": "alice@example.com",
        "Reply-To": "bob@unrelated.org",
        "Message-ID": "<abc@other-domain.net>",
    }


def test_f2_soft_signals_always_empty():
    # The former 3-soft inputs (incl. empty body) now yield zero signals.
    res = utils.check_header_signals(_non_hard_headers(), "")
    assert res["soft_signals"] == []
    assert res["hard_signals"] == []


def test_f2_non_hard_routes_to_ai_not_autojunk():
    res = utils.check_header_signals(_non_hard_headers(), "")
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
# protect / curate scope resolution at creation time (the forward-path learner
# + the _resolve_scope helper). A forward-path rule with no rule_class keeps the
# pre-existing forwarder-scoping; a classified rule resolves via _resolve_scope.
# ---------------------------------------------------------------------------

def _run_handle_new_pattern_cls(monkeypatch, classification, example):
    """Drive handle_new_pattern with arbitrary classification + example dicts,
    all IO stubbed, returning the proposed_refinement that was written."""
    captured = {}
    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": []})
    monkeypatch.setattr(learn_signals, "save_pending_signals",
                        lambda data: captured.update(pending=data))
    monkeypatch.setattr(learn_signals, "append_refinement_log", lambda event: None)
    monkeypatch.setattr(learn_signals, "_send", lambda *a, **k: True)
    ok = learn_signals.handle_new_pattern(
        classification, example, {"signals": {}, "ai_refinements": []},
        {"accounts": [{"username": "owner@example.com"}],
         "smtp": {"host": "h", "username": "owner@example.com"}},
        _QUIET_LOGGER)
    assert ok is True
    return captured["pending"]["conversations"][-1]["proposed_refinement"]


def test_handle_new_pattern_curate_with_forwarder_scopes_to_forwarder(monkeypatch):
    cls = {"kind": "new_pattern", "headline": "fundraising", "rationale": "r",
           "rule_class": "curate"}
    ex = {"filename": "x.eml", "from": "a@pac.org", "subject": "Donate",
          "forwarder": "Owner@Example.com"}
    ref = _run_handle_new_pattern_cls(monkeypatch, cls, ex)
    assert ref["scope"] == ["owner@example.com"]
    assert ref["rule_class"] == "curate"


def test_handle_new_pattern_curate_no_forwarder_is_all_per_r2(monkeypatch):
    # R2: a curate rule with no forwarder cannot be account-scoped -> "all".
    cls = {"kind": "new_pattern", "headline": "fundraising", "rationale": "r",
           "rule_class": "curate"}
    ex = {"filename": "x.eml", "from": "a@pac.org", "subject": "Donate"}  # no forwarder
    ref = _run_handle_new_pattern_cls(monkeypatch, cls, ex)
    assert ref["scope"] == "all"
    assert ref["rule_class"] == "curate"


def test_handle_new_pattern_unclassified_forward_records_protect(monkeypatch):
    # No rule_class on the classification (today's learner) -> pre-existing
    # forwarder scoping preserved, rule recorded as the effective threat class.
    ref = _run_handle_new_pattern(monkeypatch, "owner@example.com")
    assert ref["scope"] == ["owner@example.com"]
    assert ref["rule_class"] == "protect"


# ---------------------------------------------------------------------------
# R1 — the caller's EXPLICIT scope wins in propose_from_teaching. When the
# dashboard passes a scope, it must be stored unchanged regardless of what the
# model classifies the rule as (curate would otherwise re-bind to an account).
# ---------------------------------------------------------------------------

def _run_propose_from_teaching(monkeypatch, model_cls, **kwargs):
    """Drive propose_from_teaching with call_claude + all IO stubbed; return the
    proposed_refinement that was written to pending_signals (or the status dict
    when nothing was proposed)."""
    captured = {}
    monkeypatch.setattr(learn_signals, "call_claude",
                        lambda *a, **k: dict(model_cls))
    monkeypatch.setattr(learn_signals, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": []})
    monkeypatch.setattr(learn_signals, "save_pending_signals",
                        lambda data: captured.update(pending=data))
    monkeypatch.setattr(learn_signals, "append_refinement_log", lambda event: None)
    raw = (b"From: PAC <give@pac.org>\r\nSubject: Donate now\r\n\r\nPlease give.\r\n")
    out = learn_signals.propose_from_teaching(
        raw, direction="spam", user_explanation="done with these",
        api_config={"api_key": "x", "model": "m"}, logger=_QUIET_LOGGER, **kwargs)
    if out.get("status") == "proposed":
        return captured["pending"]["conversations"][-1]["proposed_refinement"]
    return out


def test_propose_explicit_scope_is_preserved_unchanged(monkeypatch):
    # Dashboard passes an explicit scope; even though the model says curate (which
    # would normally re-bind to the originating account), the explicit scope wins.
    model_cls = {"kind": "new_pattern", "headline": "fundraising", "rationale": "r",
                 "rule_class": "curate", "apply_scope": "all", "confidence": "medium"}
    ref = _run_propose_from_teaching(
        monkeypatch, model_cls, scope=["picked@example.com"],
        originating_account="other@example.com")
    assert ref["scope"] == ["picked@example.com"]   # explicit caller scope unchanged
    assert ref["rule_class"] == "curate"


def test_propose_no_scope_curate_resolves_to_originating(monkeypatch):
    # R1 inverse: no explicit scope -> derive from rule_class + originating account.
    model_cls = {"kind": "new_pattern", "headline": "fundraising", "rationale": "r",
                 "rule_class": "curate", "confidence": "medium"}  # apply_scope absent
    ref = _run_propose_from_teaching(
        monkeypatch, model_cls, originating_account="matt@example.com")
    assert ref["scope"] == ["matt@example.com"]


def test_propose_no_scope_protect_resolves_to_all(monkeypatch):
    model_cls = {"kind": "new_pattern", "headline": "phish", "rationale": "r",
                 "rule_class": "protect", "confidence": "high"}
    ref = _run_propose_from_teaching(
        monkeypatch, model_cls, originating_account="matt@example.com")
    assert ref["scope"] == "all"


def test_propose_no_scope_curate_no_account_declines(monkeypatch):
    # curate, no account, no "all" word -> must NOT silently default to "all".
    model_cls = {"kind": "new_pattern", "headline": "fundraising", "rationale": "r",
                 "rule_class": "curate", "confidence": "medium"}
    out = _run_propose_from_teaching(monkeypatch, model_cls)  # no scope, no account
    assert out["status"] == "declined"


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


# ---------------------------------------------------------------------------
# PB1 — per-account BLOCK-LIST scoping. Block-list entries gain an optional
# ``scope`` ("all" or a list of account usernames), mirroring ai_refinements.
# A MISSING scope (plain legacy string entry) is treated as "all". The live
# check_* helpers consult the scope for the CURRENT account; an entry scoped to
# one inbox does not block on the others. spam_filter._blacklist_entry_in_scope
# mirrors _refinement_in_scope.
#
# Representation chosen (migration-safe): each list in blacklist.json may hold
# either a plain string (legacy => global) OR an object {"value":..,"scope":..}.
# load_blacklist keeps the legacy flat lowercased sets for membership AND builds
# parallel {value_lower: scope} maps the checks consult.
# ---------------------------------------------------------------------------

def test_pb1_entry_in_scope_missing_is_all():
    # A legacy plain string carries no scope -> global -> blocks any account.
    assert spam_filter._blacklist_entry_in_scope("all", "anyone@x.com") is True
    assert spam_filter._blacklist_entry_in_scope(None, "anyone@x.com") is True


def test_pb1_entry_in_scope_list_matches_only_its_account():
    assert spam_filter._blacklist_entry_in_scope(["matt@x.com"], "matt@x.com") is True
    assert spam_filter._blacklist_entry_in_scope(["matt@x.com"], "other@y.com") is False


def test_pb1_entry_in_scope_case_insensitive():
    assert spam_filter._blacklist_entry_in_scope(["Matt@X.com"], "matt@x.com") is True


def test_pb1_entry_in_scope_none_account_includes_everything():
    # account_name=None means "no per-account filtering" (offline harness/tests).
    assert spam_filter._blacklist_entry_in_scope(["matt@x.com"], None) is True


def _bl_loaded(data):
    """Run a raw blacklist dict through the same normalization load_blacklist
    performs (flat sets + scope maps), without touching disk."""
    return spam_filter._ensure_list_sets(data)


def test_pb1_load_supports_mixed_string_and_object_domains():
    # Legacy string + new scoped object in the same list.
    bl = _bl_loaded({"domains": ["legacy.com",
                                 {"value": "scoped.com", "scope": ["matt@x.com"]}]})
    # Both are members (flat set, lowercased, @-stripped) ...
    assert "legacy.com" in bl["_domains_set"]
    assert "scoped.com" in bl["_domains_set"]
    # ... and the scope map records each entry's scope (string => "all").
    assert bl["_domains_scope"]["legacy.com"] == "all"
    assert bl["_domains_scope"]["scoped.com"] == ["matt@x.com"]


def test_pb1_load_object_domain_strips_leading_at():
    bl = _bl_loaded({"domains": [{"value": "@scoped.com", "scope": ["matt@x.com"]}]})
    assert "scoped.com" in bl["_domains_set"]
    assert bl["_domains_scope"]["scoped.com"] == ["matt@x.com"]


def test_pb1_load_malformed_object_is_skipped():
    # An object without a usable value must not crash and must not become a member.
    bl = _bl_loaded({"addresses": [{"scope": ["matt@x.com"]}, "real@x.com"]})
    assert "real@x.com" in bl["_addresses_set"]
    assert len(bl["_addresses_set"]) == 1


_FROM_SCOPED = 'Spammy <sales@spammyvendor.com>'


def _bl_with_scoped_domain(scope):
    return _bl_loaded({"domains": [{"value": "spammyvendor.com", "scope": scope}]})


def test_pb1_check_blacklist_scoped_blocks_its_account():
    bl = _bl_with_scoped_domain(["matt@example.com"])
    mt, mv = spam_filter.check_blacklist(_FROM_SCOPED, bl,
                                         account_name="matt@example.com")
    assert mt == "domain" and mv  # blocked for the scoped account


def test_pb1_check_blacklist_scoped_does_not_block_other_account():
    bl = _bl_with_scoped_domain(["matt@example.com"])
    mt, mv = spam_filter.check_blacklist(_FROM_SCOPED, bl,
                                         account_name="dad@example.com")
    assert (mt, mv) == (None, None)  # NOT blocked for a different account


def test_pb1_check_blacklist_legacy_string_blocks_any_account():
    bl = _bl_loaded({"domains": ["spammyvendor.com"]})  # plain string => global
    for acct in ("matt@example.com", "dad@example.com"):
        mt, _ = spam_filter.check_blacklist(_FROM_SCOPED, bl, account_name=acct)
        assert mt == "domain"


def test_pb1_check_blacklist_all_scope_blocks_everywhere():
    bl = _bl_with_scoped_domain("all")
    for acct in ("matt@example.com", "dad@example.com"):
        mt, _ = spam_filter.check_blacklist(_FROM_SCOPED, bl, account_name=acct)
        assert mt == "domain"


def test_pb1_check_blacklist_no_account_is_unchanged_behavior():
    # Back-compat: callers that don't pass account_name see every entry (today's
    # behavior). The offline path / test_phase1a rely on this.
    bl = _bl_with_scoped_domain(["matt@example.com"])
    mt, _ = spam_filter.check_blacklist(_FROM_SCOPED, bl)  # no account_name
    assert mt == "domain"


def test_pb1_check_blacklist_scoped_address_and_display_name():
    bl = _bl_loaded({
        "addresses": [{"value": "sales@spammyvendor.com", "scope": ["matt@example.com"]}],
        "display_names": [{"value": "Spammy", "scope": ["matt@example.com"]}],
    })
    # address match in scope
    assert spam_filter.check_blacklist(_FROM_SCOPED, bl,
                                       account_name="matt@example.com")[0] == "address"
    # neither matches for a different account
    assert spam_filter.check_blacklist(_FROM_SCOPED, bl,
                                       account_name="dad@example.com") == (None, None)


def test_pb1_check_subject_keywords_scoped():
    bl = _bl_loaded({"subject_keywords": [
        {"value": "winner", "scope": ["matt@example.com"]}]})
    assert spam_filter.check_subject_keywords(
        "You are a WINNER", bl, account_name="matt@example.com") == "winner"
    assert spam_filter.check_subject_keywords(
        "You are a WINNER", bl, account_name="dad@example.com") is None
    # legacy string keyword blocks any account
    bl2 = _bl_loaded({"subject_keywords": ["winner"]})
    assert spam_filter.check_subject_keywords(
        "You are a WINNER", bl2, account_name="dad@example.com") == "winner"


# ---------------------------------------------------------------------------
# PB2 — over-broad-block guardrail. is_shared_mail_domain(domain) returns True
# for major shared consumer providers (so the GUI can warn before blocking a
# whole domain and offer exact-address instead) and False for a company/org
# domain that a single sender owns. Accepts bare or @-prefixed, any case.
# ---------------------------------------------------------------------------

def test_pb2_is_shared_mail_domain_true_for_major_providers():
    for d in ("gmail.com", "googlemail.com", "yahoo.com", "ymail.com",
              "outlook.com", "hotmail.com", "live.com", "msn.com",
              "icloud.com", "me.com", "mac.com", "aol.com",
              "proton.me", "protonmail.com", "gmx.com", "zoho.com",
              "fastmail.com"):
        assert learn_signals.is_shared_mail_domain(d) is True, d


def test_pb2_is_shared_mail_domain_false_for_company_or_org():
    for d in ("rnc.org", "spammyvendor.com", "acme.com", "firstchairmarketing.com"):
        assert learn_signals.is_shared_mail_domain(d) is False, d


def test_pb2_is_shared_mail_domain_normalizes_at_and_case():
    assert learn_signals.is_shared_mail_domain("@Gmail.com") is True
    assert learn_signals.is_shared_mail_domain("GMAIL.COM") is True
    assert learn_signals.is_shared_mail_domain("") is False
    assert learn_signals.is_shared_mail_domain(None) is False


# ---------------------------------------------------------------------------
# PB3 — "Block this sender" creation. propose_from_teaching with
# rule_class="curate" + curate_mechanism="block_sender" must NOT call Claude.
# It produces a PENDING block_sender proposal whose payload is a scoped
# block-list entry (sender DOMAIN by default), scope defaulting to the
# originating account (curate default) or "all" when apply_scope=="all".
# The over-broad-domain flag is surfaced for the GUI to warn on.
# ---------------------------------------------------------------------------

_RAW_VENDOR = (b"From: Spammy Vendor <sales@spammyvendor.com>\r\n"
               b"Subject: Buy now\r\n\r\nPlease buy.\r\n")
_RAW_GMAIL = (b"From: A Person <somebody@gmail.com>\r\n"
              b"Subject: hi\r\n\r\nhello.\r\n")


def _run_block_sender(monkeypatch, raw=_RAW_VENDOR, **kwargs):
    """Drive propose_from_teaching down the block_sender path with all IO
    stubbed. call_claude must NEVER be invoked. Returns (out, captured_conv)."""
    captured = {}

    def _no_claude(*a, **k):
        raise AssertionError("call_claude must NOT run for block_sender")

    monkeypatch.setattr(learn_signals, "call_claude", _no_claude)
    monkeypatch.setattr(learn_signals, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": []})
    monkeypatch.setattr(learn_signals, "save_pending_signals",
                        lambda data: captured.update(pending=data))
    monkeypatch.setattr(learn_signals, "append_refinement_log", lambda e: None)
    out = learn_signals.propose_from_teaching(
        raw, direction="spam", user_explanation="done with these",
        rule_class="curate", curate_mechanism="block_sender",
        api_config={"api_key": "x", "model": "m"}, logger=_QUIET_LOGGER, **kwargs)
    conv = None
    if out.get("status") == "proposed":
        conv = captured["pending"]["conversations"][-1]
    return out, conv


def test_pb3_block_sender_proposes_domain_by_default(monkeypatch):
    out, conv = _run_block_sender(
        monkeypatch, originating_account="matt@example.com")
    assert out["status"] == "proposed"
    assert conv["kind"] == "block_sender_proposal"
    entry = conv["blocklist_entry"]
    assert entry["kind"] == "domain"
    assert entry["value"] == "spammyvendor.com"          # bare, @-stripped
    assert entry["scope"] == ["matt@example.com"]        # curate default = originating
    assert out["over_broad"] is False                    # company domain


def test_pb3_block_sender_scope_all_when_apply_scope_all(monkeypatch):
    out, conv = _run_block_sender(
        monkeypatch, apply_scope="all", originating_account="matt@example.com")
    assert conv["blocklist_entry"]["scope"] == "all"


def test_pb3_block_sender_explicit_scope_wins(monkeypatch):
    # Dashboard passes an explicit scope (its account picker) — it wins unchanged.
    out, conv = _run_block_sender(
        monkeypatch, scope=["picked@example.com"],
        originating_account="other@example.com")
    assert conv["blocklist_entry"]["scope"] == ["picked@example.com"]


def test_pb3_block_sender_flags_over_broad_shared_domain(monkeypatch):
    out, conv = _run_block_sender(
        monkeypatch, raw=_RAW_GMAIL, originating_account="matt@example.com")
    assert out["over_broad"] is True
    # Still defaults to domain (engine flags; the GUI offers exact-address next task).
    assert conv["blocklist_entry"]["kind"] == "domain"
    assert conv["blocklist_entry"]["value"] == "gmail.com"
    assert conv["blocklist_entry"]["over_broad"] is True


def test_pb3_block_sender_explicit_address_kind(monkeypatch):
    # The GUI may request an exact-address block instead of the whole domain.
    out, conv = _run_block_sender(
        monkeypatch, raw=_RAW_GMAIL, block_kind="address",
        originating_account="matt@example.com")
    entry = conv["blocklist_entry"]
    assert entry["kind"] == "address"
    assert entry["value"] == "somebody@gmail.com"


def test_pb3_block_sender_curate_no_account_declines(monkeypatch):
    # curate block_sender, no explicit scope, no originating account, no "all"
    # word -> must DECLINE (never silently global), mirroring content curate.
    out, _ = _run_block_sender(monkeypatch)  # no scope, no account, no apply_scope
    assert out["status"] == "declined"


# ---------------------------------------------------------------------------
# PB4 — block_sender APPROVAL writes the scoped block-list entry and is then
# enforced per-account. config_io.add_blocklist_entry is the writer;
# config_io.apply_blocklist_proposal_from_pending is the dashboard approval
# path (parallels apply_refinement_from_pending).
# ---------------------------------------------------------------------------

def test_pb4_add_blocklist_entry_writes_scoped_object(monkeypatch):
    saved = {}
    monkeypatch.setattr(config_io, "load_blacklist",
                        lambda: {"addresses": [], "domains": [],
                                 "display_names": [], "subject_keywords": []})
    monkeypatch.setattr(config_io, "save_blacklist", lambda bl: saved.update(bl=bl))
    config_io.add_blocklist_entry("spammyvendor.com", "domain", ["matt@example.com"])
    bl = saved["bl"]
    assert {"value": "spammyvendor.com", "scope": ["matt@example.com"]} in bl["domains"]


def test_pb4_add_blocklist_entry_address_and_global(monkeypatch):
    saved = {}
    monkeypatch.setattr(config_io, "load_blacklist",
                        lambda: {"addresses": [], "domains": [],
                                 "display_names": [], "subject_keywords": []})
    monkeypatch.setattr(config_io, "save_blacklist", lambda bl: saved.update(bl=bl))
    config_io.add_blocklist_entry("a@b.com", "address", "all")
    assert {"value": "a@b.com", "scope": "all"} in saved["bl"]["addresses"]


def test_pb4_add_blocklist_entry_dedupes_same_value(monkeypatch):
    # Adding the same domain with a different scope must not create a duplicate
    # value row; it updates the existing row's scope (idempotent re-block).
    bl0 = {"addresses": [], "subject_keywords": [], "display_names": [],
           "domains": [{"value": "spammyvendor.com", "scope": ["matt@example.com"]}]}
    saved = {}
    monkeypatch.setattr(config_io, "load_blacklist", lambda: bl0)
    monkeypatch.setattr(config_io, "save_blacklist", lambda bl: saved.update(bl=bl))
    config_io.add_blocklist_entry("spammyvendor.com", "domain", "all")
    domains = saved["bl"]["domains"]
    assert len(domains) == 1
    assert domains[0]["value"] == "spammyvendor.com"
    assert domains[0]["scope"] == "all"


def _block_sender_conv(scope=("matt@example.com",), kind="domain",
                       value="spammyvendor.com"):
    return {
        "id": "SFID-20260601-009",
        "kind": "block_sender_proposal",
        "status": "awaiting_reply",
        "forwarder": "matt@example.com",
        "blocklist_entry": {"value": value, "kind": kind,
                            "scope": list(scope) if isinstance(scope, tuple) else scope},
    }


def test_pb4_apply_blocklist_proposal_writes_entry(monkeypatch):
    conv = _block_sender_conv()
    written = {}
    monkeypatch.setattr(config_io, "load_pending_signals",
                        lambda: {"version": "1.0", "conversations": [conv]})
    monkeypatch.setattr(config_io, "save_pending_signals", lambda d: None)
    monkeypatch.setattr(config_io, "append_refinement_log", lambda e: None)
    monkeypatch.setattr(config_io, "load_blacklist",
                        lambda: {"addresses": [], "domains": [],
                                 "display_names": [], "subject_keywords": []})
    monkeypatch.setattr(config_io, "save_blacklist", lambda bl: written.update(bl=bl))
    res = config_io.apply_blocklist_proposal_from_pending(conv["id"], source="dashboard")
    assert res is not None
    assert {"value": "spammyvendor.com", "scope": ["matt@example.com"]} \
        in written["bl"]["domains"]
    assert conv["status"] == "approved"


def test_pb4_written_entry_is_enforced_per_account():
    # End-to-end through the SAME normalization the live filter uses: a written
    # scoped domain entry blocks its account and not another.
    bl = _bl_loaded({"domains": [{"value": "spammyvendor.com",
                                  "scope": ["matt@example.com"]}]})
    assert spam_filter.check_blacklist(
        "x <a@spammyvendor.com>", bl, account_name="matt@example.com")[0] == "domain"
    assert spam_filter.check_blacklist(
        "x <a@spammyvendor.com>", bl, account_name="dad@example.com") == (None, None)


# ---------------------------------------------------------------------------
# PB5 — block_like_this and protect still produce CONTENT ai_refinements
# (the existing curate/protect flow), unchanged. Only block_sender skips Claude.
# ---------------------------------------------------------------------------

def test_pb5_curate_block_like_this_still_calls_claude_and_makes_refinement(monkeypatch):
    model_cls = {"kind": "new_pattern", "headline": "fundraising blasts",
                 "rationale": "r", "rule_class": "curate", "confidence": "medium"}
    ref = _run_propose_from_teaching(
        monkeypatch, model_cls, rule_class="curate",
        curate_mechanism="block_like_this", scope=["matt@example.com"])
    # A normal content refinement (NOT a block_sender entry).
    assert ref["headline"] == "fundraising blasts"
    assert ref["rule_class"] == "curate"
    assert ref["scope"] == ["matt@example.com"]


def test_pb5_protect_still_calls_claude_and_makes_refinement(monkeypatch):
    model_cls = {"kind": "new_pattern", "headline": "paypal phish",
                 "rationale": "r", "rule_class": "protect", "confidence": "high"}
    ref = _run_propose_from_teaching(
        monkeypatch, model_cls, rule_class="protect", scope="all")
    assert ref["headline"] == "paypal phish"
    assert ref["rule_class"] == "protect"


# ---------------------------------------------------------------------------
# PB6 — the dead hard_rule machinery is GONE. The learner no longer exposes
# _validate_hard_rule, no longer emits hard_rule on a produced refinement, and
# the prompt schema no longer mentions hard_rule.
# ---------------------------------------------------------------------------

def test_pb6_validate_hard_rule_removed():
    assert not hasattr(learn_signals, "_validate_hard_rule")


def test_pb6_teaching_refinement_never_emits_hard_rule():
    r = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R",
         "rule_class": "protect",
         "hard_rule": {"type": "sender_domain", "value": "spammers.biz"}},
        verdict="spam", scope="all", refinement_id="R1", evidence_name="e")
    assert "hard_rule" not in r
    assert "signal_type" not in r  # vestigial hard/soft marker also gone


def test_pb6_handle_new_pattern_never_emits_hard_rule(monkeypatch):
    cls = {"kind": "new_pattern", "headline": "h", "rationale": "r",
           "hard_rule": {"type": "subject_keyword", "value": "winner"}}
    ex = {"filename": "x.eml", "from": "a@b.com", "subject": "s",
          "forwarder": "owner@example.com"}
    ref = _run_handle_new_pattern_cls(monkeypatch, cls, ex)
    assert "hard_rule" not in ref
    assert "signal_type" not in ref


def test_pb6_prompt_schemas_no_longer_mention_hard_rule():
    assert "hard_rule" not in learn_signals.TEACH_SYSTEM
    assert "hard_rule" not in learn_signals.LEARNER_SYSTEM
    spam = learn_signals.build_teach_prompt(
        {"from": "a@b.com", "subject": "s", "plain_text_body": "b"},
        direction="spam", active_refinements=[])
    assert "hard_rule" not in spam
    learner_p = learn_signals.build_learner_prompt(
        [{"filename": "x.eml", "from": "a@b.com", "subject": "s",
          "plain_text_body": "b", "received_headers": []}], [])
    assert "hard_rule" not in learner_p


# ---------------------------------------------------------------------------
# FP-AUTH — deterministic, auth-gated fix for the authenticated-sender false
# positive (Jeffries). Two parts:
#   (a) leading zero-width / whitespace preheader padding is normalized before
#       classification, and
#   (b) the over-broad legacy "filter-evasion" learned signals are suppressed
#       ONLY for genuinely authenticated, brand-matched (true RULE 1) senders.
# These are pure/deterministic — no API — so they belong in the unit suite.
# ---------------------------------------------------------------------------

# A legacy learned signal set that contains the over-broad evasion signal plus
# two legitimate, concrete signals that must NEVER be suppressed.
_EVASION_SIGNALS = {
    "signals": {
        "hard_signals": [
            "Benign conversational text block (meeting scheduling, personal "
            "reflection) prepended before promotional/scam content - used as "
            "filter evasion",
            "CSS class names using random nature/object word combinations "
            "(e.g., 'nebula-quartz') in HTML emails",
            "Homoglyph substitution in subject lines: 'I' replaced with 'l'",
        ],
        "soft_signals": [
            "Mismatch between casual/personal opening paragraphs and "
            "promotional closing content",
            "Points/rewards expiration urgency with specific dollar amounts",
        ],
    }
}


def test_fpauth_padding_strips_leading_zero_width_and_whitespace():
    # 232 zero-width non-joiners interleaved with spaces, then real content.
    padded = ("‌ " * 232) + "Janet, I hate to interrupt your Saturday."
    out = spam_filter._normalize_leading_padding(padded)
    assert out.startswith("Janet, I hate to interrupt")
    assert "‌" not in out[:1]            # no leading zero-width left
    # all four zero-width variants + BOM are stripped when leading
    assert spam_filter._normalize_leading_padding(
        "​‌‍﻿\n\t  hello") == "hello"


def test_fpauth_padding_preserves_interior_and_empty():
    # Interior zero-width / whitespace is NOT touched (only the leading run).
    assert spam_filter._normalize_leading_padding(
        "real‌ text") == "real‌ text"
    assert spam_filter._normalize_leading_padding("") == ""
    assert spam_filter._normalize_leading_padding("no padding") == "no padding"


def test_fpauth_padding_normalized_in_user_message():
    # End-to-end: build_user_message must place real content (not padding) in
    # the first-500-char window the classifier sees.
    md = {
        "from_email": "info@example.org",
        "from_display_name": "Sender",
        "plain_text_body": ("‌ " * 232) + "REAL CONTENT STARTS HERE.",
        "subject": "s",
    }
    um = spam_filter.build_user_message(md)
    assert "REAL CONTENT STARTS HERE." in um
    # The padding must not survive into the prompt body window.
    assert "‌‌" not in um


def test_fpauth_authenticated_brand_matched_true_rule1():
    # DKIM/DMARC pass AND an authenticated domain aligns with the From domain.
    auth = {"dkim": "pass", "dmarc": "pass",
            "authenticated_domains": ["bounce.hakeemjeffries.com",
                                      "hakeemjeffries.com"],
            "from_domain": "hakeemjeffries.com"}
    assert spam_filter.is_authenticated_brand_matched(auth) is True


def test_fpauth_unauthenticated_is_not_brand_matched():
    # No DKIM/DMARC pass -> gate is False (Instagram/Dashlane case): the prompt
    # is left untouched for these so their boundary behavior never shifts.
    auth = {"dkim": "none", "dmarc": "none",
            "authenticated_domains": [], "from_domain": "mail.instagram.com"}
    assert spam_filter.is_authenticated_brand_matched(auth) is False


def test_fpauth_authenticated_to_unrelated_domain_is_not_brand_matched():
    # Authenticates a domain UNRELATED to the From domain -> not RULE 1.
    auth = {"dkim": "pass", "dmarc": "pass",
            "authenticated_domains": ["randomthrowaway.test"],
            "from_domain": "paypal.com"}
    assert spam_filter.is_authenticated_brand_matched(auth) is False


def test_fpauth_subdomain_and_parent_alignment():
    assert spam_filter._domain_is_brand_match("hakeemjeffries.com",
                                              "bounce.hakeemjeffries.com")
    assert spam_filter._domain_is_brand_match("mail.example.com", "example.com")
    assert not spam_filter._domain_is_brand_match("evil.com", "example.com")
    assert not spam_filter._domain_is_brand_match("", "example.com")


def test_fpauth_suppression_removes_only_evasion_signal():
    # With suppression ON, the over-broad evasion hard/soft signals are gone,
    # but the concrete CSS / homoglyph / rewards signals REMAIN.
    p_on = spam_filter.build_classifier_prompt(
        _EVASION_SIGNALS, None, suppress_evasion_signals=True)
    assert "used as filter evasion" not in p_on
    assert "casual/personal opening paragraphs" not in p_on
    assert "CSS class names using random" in p_on
    assert "Homoglyph substitution" in p_on
    assert "Points/rewards expiration urgency" in p_on


def test_fpauth_default_prompt_unchanged_keeps_evasion_signal():
    # Default (no suppression) is byte-identical to the historical behavior and
    # still contains the evasion signal — so unauthenticated mail is unaffected.
    p_default = spam_filter.build_classifier_prompt(_EVASION_SIGNALS, None)
    p_explicit_off = spam_filter.build_classifier_prompt(
        _EVASION_SIGNALS, None, suppress_evasion_signals=False)
    assert p_default == p_explicit_off
    assert "used as filter evasion" in p_default


# ---------------------------------------------------------------------------
# Pending-card label by proposal type. The Signal History "waiting on you"
# card used to hardcode "AI refinement (soft)" for every spam_example_proposal,
# which mislabels intent-bearing proposals (e.g. a "let it through" legitimate
# rule shown as soft AI). dashboard.pending_proposal_label maps the proposed
# refinement's verdict/rule_class to the owner-facing label. Pure (no tk, no
# IO) so the type->label mapping is unit-tested headlessly; block_sender
# proposals keep their own "Block sender …" rendering and never use this.
# ---------------------------------------------------------------------------

def test_pending_label_legitimate_is_let_it_through():
    # verdict legitimate (rule_class is None for legit rules) -> let-it-through.
    assert dashboard.pending_proposal_label(
        {"verdict": "legitimate", "rule_class": None}) == "Let it through (legitimate)"


def test_pending_label_protect_is_threat():
    assert dashboard.pending_proposal_label(
        {"verdict": "spam", "rule_class": "protect"}) == "Protect — threat"


def test_pending_label_curate_is_dont_want_it():
    assert dashboard.pending_proposal_label(
        {"verdict": "spam", "rule_class": "curate"}) == "Curate — don't want it"


def test_pending_label_legacy_spam_no_rule_class_is_neutral():
    # Legacy proposal: spam verdict, no rule_class -> neutral "Learned rule"
    # (NOT the misleading old "AI refinement (soft)" wording).
    assert dashboard.pending_proposal_label(
        {"verdict": "spam"}) == "Learned rule"
    assert dashboard.pending_proposal_label({}) == "Learned rule"


def test_pending_label_legitimate_wins_over_stray_rule_class():
    # A legitimate rule is neither protect nor curate; verdict is decisive.
    assert dashboard.pending_proposal_label(
        {"verdict": "legitimate", "rule_class": "curate"}) == "Let it through (legitimate)"


def test_pending_label_garbage_rule_class_falls_back_to_neutral():
    # Unknown/garbage rule_class on a spam rule must not crash or mislabel.
    assert dashboard.pending_proposal_label(
        {"verdict": "spam", "rule_class": "nonsense"}) == "Learned rule"

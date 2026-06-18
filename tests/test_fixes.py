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
    # SECURITY (audit C5/ARC): the verified result living ONLY in
    # ARC-Authentication-Results must NOT grant a proven sender — ARC is
    # forgeable and is no longer trusted. Such mail is judged on content.
    s = utils.summarize_authentication({"ARC-Authentication-Results": NBC_ARC}, "corp.example.com")
    assert s["spf"] == "none"
    assert s["dkim"] == "none"
    assert s["dmarc"] == "none"
    assert "corp.example.com" not in s["authenticated_domains"]
    assert s["authenticated_domains"] == []


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


# ---------------------------------------------------------------------------
# NOT SPAM alias — "NOT SPAM" (and variants) must be recognized as an alias
# for the canonical "False Positive" command, flowing through the identical
# handler path. Regression checks confirm existing commands are unaffected.
# ---------------------------------------------------------------------------

def test_not_spam_upper_resolves_to_false_positive():
    assert spam_filter.detect_email_command("NOT SPAM") == "False Positive"


def test_not_spam_lower_resolves_to_false_positive():
    assert spam_filter.detect_email_command("not spam") == "False Positive"


def test_not_spam_mixed_case_resolves_to_false_positive():
    assert spam_filter.detect_email_command("Not Spam") == "False Positive"


def test_not_spam_fwd_upper_resolves_to_false_positive():
    assert spam_filter.detect_email_command("Fwd: NOT SPAM") == "False Positive"


def test_not_spam_fwd_lower_resolves_to_false_positive():
    assert spam_filter.detect_email_command("FWD: not spam") == "False Positive"


def test_not_spam_fw_mixed_resolves_to_false_positive():
    assert spam_filter.detect_email_command("Fw: Not Spam") == "False Positive"


# Regression: existing commands must still resolve correctly.

def test_regression_spam_example():
    assert spam_filter.detect_email_command("Fwd: SPAM Example") == "SPAM Example"


def test_regression_false_positive_fwd():
    assert spam_filter.detect_email_command("Fwd: False Positive") == "False Positive"


def test_regression_whitelist_direct():
    assert spam_filter.detect_email_command("Whitelist") == "Direct Whitelist"


def test_regression_blacklist_direct():
    assert spam_filter.detect_email_command("Blacklist") == "Direct Blacklist"


# ---------------------------------------------------------------------------
# Fix B — _owner_identities and broadened _command_sender_is_owner
# ---------------------------------------------------------------------------

def _cfg(accounts=None, smtp_username="main@example.com",
         smtp_from=None):
    """Build a minimal config dict for owner-identity tests."""
    accts = accounts if accounts is not None else [
        {"username": "main@example.com", "enabled": True},
        {"username": "commerce@example.com", "enabled": True},
    ]
    smtp = {"host": "smtp.example.com", "username": smtp_username}
    if smtp_from:
        smtp["from_address"] = smtp_from
    return {"accounts": accts, "smtp": smtp}


def test_fix_b_identities_includes_enabled_accounts():
    cfg = _cfg()
    ids = spam_filter._owner_identities(cfg)
    assert "main@example.com" in ids
    assert "commerce@example.com" in ids


def test_fix_b_identities_includes_smtp_username_and_from_address():
    cfg = _cfg(smtp_username="smtp@example.com", smtp_from="noreply@example.com")
    ids = spam_filter._owner_identities(cfg)
    assert "smtp@example.com" in ids
    assert "noreply@example.com" in ids


def test_fix_b_identities_excludes_disabled_account():
    cfg = _cfg(accounts=[
        {"username": "active@example.com", "enabled": True},
        {"username": "inactive@example.com", "enabled": False},
    ])
    ids = spam_filter._owner_identities(cfg)
    assert "active@example.com" in ids
    assert "inactive@example.com" not in ids


def test_fix_b_identities_case_insensitive_lowercased():
    cfg = _cfg(accounts=[{"username": "Owner@Example.COM", "enabled": True}],
               smtp_username="SMTP@Example.COM")
    ids = spam_filter._owner_identities(cfg)
    assert "owner@example.com" in ids
    assert "smtp@example.com" in ids


def test_fix_b_sender_is_polled_account_still_passes():
    # Original behaviour: polled account username always accepted.
    account = {"username": "commerce@example.com"}
    assert spam_filter._command_sender_is_owner(
        "commerce@example.com", account, _cfg()) is True


def test_fix_b_sender_is_other_owner_identity_passes():
    # Cross-account: owner sends from main@ into commerce@ inbox.
    account = {"username": "commerce@example.com"}
    cfg = _cfg()  # main@example.com is a configured enabled account
    assert spam_filter._command_sender_is_owner(
        "main@example.com", account, cfg) is True


def test_fix_b_sender_is_smtp_identity_passes():
    # Owner's SMTP from_address is also trusted.
    account = {"username": "commerce@example.com"}
    cfg = _cfg(smtp_from="noreply@example.com")
    assert spam_filter._command_sender_is_owner(
        "noreply@example.com", account, cfg) is True


def test_fix_b_stranger_rejected_even_with_config():
    account = {"username": "commerce@example.com"}
    cfg = _cfg()
    assert spam_filter._command_sender_is_owner(
        "attacker@evil.com", account, cfg) is False


def test_fix_b_empty_sender_rejected():
    account = {"username": "commerce@example.com"}
    assert spam_filter._command_sender_is_owner("", account, _cfg()) is False


def test_fix_b_no_config_still_works_for_polled_account():
    # Backward compat: no config supplied -> only polled account username accepted.
    account = {"username": "owner@example.com"}
    assert spam_filter._command_sender_is_owner(
        "owner@example.com", account) is True
    assert spam_filter._command_sender_is_owner(
        "other@example.com", account) is False


# ---------------------------------------------------------------------------
# Fix C — Reply-To header in outbound mail
# ---------------------------------------------------------------------------

import email as _email_module
from email.mime.text import MIMEText as _MIMEText


def _capture_send_email(monkeypatch, to_addr):
    """Call spam_filter.send_email with SMTP stubbed; return the MIMEText msg."""
    from utils import smtp_login as _real_smtp_login
    captured = {}

    class _FakeServer:
        def sendmail(self, frm, to, msg_str):
            captured["msg_str"] = msg_str

        def quit(self):
            pass

    monkeypatch.setattr("spam_filter.smtp_login", lambda cfg: _FakeServer(),
                        raising=False)
    # smtp_login is imported inside send_email as `from utils import smtp_login`
    import utils as _utils_mod
    monkeypatch.setattr(_utils_mod, "smtp_login", lambda cfg: _FakeServer())

    cfg = {"smtp": {"host": "smtp.example.com", "username": "main@example.com",
                    "from_address": "main@example.com", "port": 587,
                    "use_starttls": True},
           "summary": {"recipient_address": "main@example.com"}}

    import logging as _log
    spam_filter.send_email(cfg, "Test Subject", "Test body.",
                           _log.getLogger("test"), to_addr=to_addr)
    if "msg_str" not in captured:
        return None
    return _email_module.message_from_string(captured["msg_str"])


def test_fix_c_send_email_sets_reply_to(monkeypatch):
    msg = _capture_send_email(monkeypatch, "commerce@example.com")
    assert msg is not None
    assert msg["Reply-To"] == "commerce@example.com"


def test_fix_c_send_email_reply_to_equals_to(monkeypatch):
    msg = _capture_send_email(monkeypatch, "another@example.com")
    assert msg is not None
    assert msg["Reply-To"] == msg["To"]


def test_fix_c_learner_send_sets_reply_to(monkeypatch):
    """learn_signals._send must also set Reply-To = to_addr."""
    captured = {}

    class _FakeServer:
        def sendmail(self, frm, to, msg_str):
            captured["msg_str"] = msg_str

        def quit(self):
            pass

    import utils as _utils_mod
    monkeypatch.setattr(_utils_mod, "smtp_login", lambda cfg: _FakeServer())

    cfg = {"smtp": {"host": "smtp.example.com", "username": "main@example.com",
                    "from_address": "main@example.com"}}

    import logging as _log
    learn_signals._send(cfg, "commerce@example.com", "Proposal",
                        "Is this spam?", _log.getLogger("test"))

    assert "msg_str" in captured
    parsed = _email_module.message_from_string(captured["msg_str"])
    assert parsed["Reply-To"] == "commerce@example.com"


# ---------------------------------------------------------------------------
# C1 (auth gate) — an owner-LOOKING command/approval is honored ONLY when the
# From-domain is cryptographically authenticated (SPF/DKIM/DMARC pass + strict
# alignment). A spoof (no/failing auth) or an alignment-breaking forward fails.
# ---------------------------------------------------------------------------

# Realistic Gmail-style Authentication-Results aligned to the owner's domain.
OWNER_AR = (
    "mx.google.com; "
    "dkim=pass header.i=@firstchairmarketing.com header.s=sel header.b=AbCdEf; "
    "spf=pass (google.com: domain of bounce@firstchairmarketing.com designates "
    "1.2.3.4 as permitted sender) smtp.mailfrom=bounce@firstchairmarketing.com; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=firstchairmarketing.com"
)

# Auth that passes only for a DIFFERENT domain than the From-domain.
OTHER_AR = (
    "mx.google.com; "
    "dkim=pass header.i=@elsewhere.example header.s=sel header.b=AbCdEf; "
    "spf=pass smtp.mailfrom=bounce@elsewhere.example; "
    "dmarc=pass (p=REJECT) header.from=elsewhere.example"
)


# Minimal account/config whose hosts deliberately do NOT match anything in
# these path-(a) tests, so path (b) bails out (no own-host match, no
# _mime_msg) and ONLY the strict SPF/DKIM/DMARC alignment path is exercised.
NO_MATCH_ACCT = {"imap_host": "imap.example.com"}
NO_MATCH_CONFIG = {"smtp": {"host": "smtp.example.com"}}


def test_authgate_true_for_aligned_authenticated_from():
    md = {"auth_results": OWNER_AR}
    assert spam_filter._command_auth_ok(
        md, "matt@firstchairmarketing.com",
        NO_MATCH_ACCT, NO_MATCH_CONFIG) is True


def test_authgate_false_for_missing_auth_headers_spoof():
    # No Authentication-Results at all — a forged From with nothing to back it.
    md = {"auth_results": "", "arc_auth_results": "",
          "received_spf": "", "dkim_signature": ""}
    assert spam_filter._command_auth_ok(
        md, "matt@firstchairmarketing.com",
        NO_MATCH_ACCT, NO_MATCH_CONFIG) is False


def test_authgate_false_when_auth_aligns_to_different_domain():
    # Auth passes, but for elsewhere.example — NOT the From-domain. Proves the
    # gate checks alignment, not a bare spf=pass.
    md = {"auth_results": OTHER_AR}
    assert spam_filter._command_auth_ok(
        md, "matt@firstchairmarketing.com",
        NO_MATCH_ACCT, NO_MATCH_CONFIG) is False


def test_authgate_false_for_empty_from_email():
    md = {"auth_results": OWNER_AR}
    assert spam_filter._command_auth_ok(
        md, "", NO_MATCH_ACCT, NO_MATCH_CONFIG) is False


# ---------------------------------------------------------------------------
# C1 path (b) — authenticated submission into the account's OWN mail server,
# proven by the server-written Received chain. Own host = box5275.bluehost.com
# (the live Bluehost host). These messages carry NO Authentication-Results, so
# path (a) cannot fire — only path (b) can return True.
# ---------------------------------------------------------------------------

import email as _email  # noqa: E402

# Own-host account/config for path (b) tests.
BH_ACCT = {"imap_host": "box5275.bluehost.com"}
BH_CONFIG = {"smtp": {"host": "box5275.bluehost.com"}}


def _md_from_received(received_block: str) -> dict:
    """Build a msg_data dict with a real parsed _mime_msg from a raw header
    block. NO Authentication-Results, so path (a) is dead and only path (b)
    can pass."""
    raw = received_block.rstrip("\n") + "\n\nbody\n"
    msg = _email.message_from_string(raw)
    return {
        "auth_results": "", "arc_auth_results": "",
        "received_spf": "", "dkim_signature": "",
        "_mime_msg": msg,
    }


def test_authgate_pathb_genuine_bluehost_chain_true():
    # Verbatim genuine-mail evidence (UID 43023): hop 1 is the internal LMTP
    # self-relay (skip), hop 2 is the authenticated submission (esmtpsa).
    received = (
        "Received: from box5275.bluehost.com by box5275.bluehost.com with LMTP "
        "id abc123 for <matt@nthmonkey.com>\n"
        "Received: from [72.80.205.252] (port=56467 helo=[192.168.1.202]) "
        "by box5275.bluehost.com with esmtpsa (TLS1.3) tls "
        "TLS_AES_256_GCM_SHA384 (Exim 4.99.2) "
        "(envelope-from <matt@nthmonkey.com>) id def456 for matt@nthmonkey.com"
    )
    md = _md_from_received(received)
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is True


def test_authgate_pathb_webmail_self_hop_esmtpsa_true():
    # cPanel webmail: a single self-hop (from box5275 by box5275 with esmtpsa).
    # The esmtpsa check fires before the self-relay continue, so it's accepted.
    received = (
        "Received: from box5275.bluehost.com ([127.0.0.1]) "
        "by box5275.bluehost.com with esmtpsa (TLS1.3) id ghi789 "
        "for matt@nthmonkey.com"
    )
    md = _md_from_received(received)
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is True


def test_authgate_pathb_forged_external_entry_esmtp_false():
    # External MX delivery: entry hop is "from mail.attacker.example by
    # box5275 with esmtp" — unauthenticated handoff. Rejected.
    received = (
        "Received: from mail.attacker.example "
        "by box5275.bluehost.com with esmtp id jkl012 for matt@nthmonkey.com"
    )
    md = _md_from_received(received)
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is False


def test_authgate_pathb_fake_deep_esmtpsa_below_entry_false():
    # Attacker plants a forged "with esmtpsa by box5275" Received BELOW the real
    # unauthenticated entry hop. The walk stops at the entry hop (top-down) and
    # never reaches the forged line. Rejected. Proves the top-down stop.
    received = (
        "Received: from mail.attacker.example "
        "by box5275.bluehost.com with esmtp id mno345 for matt@nthmonkey.com\n"
        "Received: from [10.0.0.9] "
        "by box5275.bluehost.com with esmtpsa id pqr678 for matt@nthmonkey.com"
    )
    md = _md_from_received(received)
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is False


def test_authgate_pathb_with_local_entry_false():
    # Same-box script/PHP submission (with local) — any co-tenant could emit
    # this without authenticating. Rejected.
    received = (
        "Received: from box5275.bluehost.com "
        "by box5275.bluehost.com with local id stu901 for matt@nthmonkey.com"
    )
    md = _md_from_received(received)
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is False


def test_authgate_pathb_no_received_headers_false():
    # IMAP-APPENDed forgery: no server-written Received chain at all. Rejected.
    msg = _email.message_from_string("Subject: hi\n\nbody\n")
    md = {"auth_results": "", "arc_auth_results": "",
          "received_spf": "", "dkim_signature": "", "_mime_msg": msg}
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is False


def test_authgate_pathb_different_by_host_esmtpsa_false():
    # Topmost `by` is a different host (mx.google.com), not our own server.
    # Path (b) bails at the first hop. With no aligned stamps either, the gate
    # is False overall — proves path (b) does not trust foreign servers.
    received = (
        "Received: from [10.0.0.9] "
        "by mx.google.com with esmtpsa id vwx234 for matt@nthmonkey.com"
    )
    md = _md_from_received(received)
    assert spam_filter._command_auth_ok(
        md, "matt@nthmonkey.com", BH_ACCT, BH_CONFIG) is False


def test_authgate_patha_still_true_with_foreign_received_chain():
    # Layering proof: aligned stamps alone (path a) authenticate even when the
    # Received chain is foreign / non-own-host. From-domain matches OWNER_AR.
    received = (
        "Received: from mail-sor.google.com "
        "by mx.google.com with esmtps id yz567 "
        "for matt@firstchairmarketing.com"
    )
    raw = received + "\n\nbody\n"
    msg = _email.message_from_string(raw)
    md = {"auth_results": OWNER_AR, "arc_auth_results": "",
          "received_spf": "", "dkim_signature": "", "_mime_msg": msg}
    # Own-host set is box5275; the chain's `by` is mx.google.com, so path (b)
    # returns False — but path (a) (aligned OWNER_AR) makes the gate True.
    assert spam_filter._command_auth_ok(
        md, "matt@firstchairmarketing.com", BH_ACCT, BH_CONFIG) is True


# ---------------------------------------------------------------------------
# B3 + C1 (predictability) — SFIDs / R-IDs are unguessable random tokens that
# cannot collide. Both SFID generators emit a byte-identical format so one
# resolver regex matches both.
# ---------------------------------------------------------------------------

import re as _re  # noqa: E402

_SFID_RE = _re.compile(r"^SFID-\d{8}-[0-9a-f]+$")
_RID_RE = _re.compile(r"^R-\d{8}-[0-9a-f]+$")


def test_b3_generate_sfid_matches_random_format():
    assert _SFID_RE.match(spam_filter.generate_sfid({"conversations": []}))


def test_b3_next_sfid_matches_random_format():
    assert _SFID_RE.match(learn_signals.next_sfid({"conversations": []}))


def test_b3_both_sfid_generators_identical_format():
    a = spam_filter.generate_sfid({"conversations": []})
    b = learn_signals.next_sfid({"conversations": []})
    # Same prefix shape and token alphabet (the resolver regex must match both).
    assert _SFID_RE.match(a) and _SFID_RE.match(b)


def test_b3_generate_sfid_no_dupes_over_1000():
    seen = set()
    for _ in range(1000):
        sfid = spam_filter.generate_sfid({"conversations": []})
        assert sfid not in seen
        seen.add(sfid)
    assert len(seen) == 1000


def test_b3_next_sfid_no_dupes_over_1000():
    seen = set()
    for _ in range(1000):
        sfid = learn_signals.next_sfid({"conversations": []})
        assert sfid not in seen
        seen.add(sfid)
    assert len(seen) == 1000


def test_b3_generate_sfid_regenerates_on_collision(monkeypatch):
    # Force the token source to return a colliding value once, then a fresh one.
    # spam_filter binds random_token at import (`from utils import random_token`),
    # so patch the name in the spam_filter module namespace.
    today = _datetime_now_strftime()
    colliding = f"SFID-{today}-deadbeef"
    tokens = iter(["deadbeef", "cafef00d"])
    monkeypatch.setattr(spam_filter, "random_token", lambda *a, **k: next(tokens))
    out = spam_filter.generate_sfid({"conversations": [{"id": colliding}]})
    assert out == f"SFID-{today}-cafef00d"
    assert out != colliding


def test_b3_next_sfid_regenerates_on_collision(monkeypatch):
    # learn_signals.next_sfid re-imports random_token locally at call time, so
    # patch the source symbol on the utils module.
    today = _datetime_now_strftime()
    colliding = f"SFID-{today}-deadbeef"
    tokens = iter(["deadbeef", "cafef00d"])
    monkeypatch.setattr(utils, "random_token", lambda *a, **k: next(tokens))
    out = learn_signals.next_sfid({"conversations": [{"id": colliding}]})
    assert out == f"SFID-{today}-cafef00d"
    assert out != colliding


def test_b3_next_refinement_id_matches_random_format(monkeypatch):
    # Isolate from on-disk pending state.
    monkeypatch.setattr(learn_signals, "load_pending_signals",
                        lambda *a, **k: {"conversations": []})
    assert _RID_RE.match(learn_signals.next_refinement_id({"ai_refinements": []}))


def _datetime_now_strftime():
    from datetime import datetime as _dt
    return _dt.now().strftime("%Y%m%d")


# ---------------------------------------------------------------------------
# Backward-compat: the permissive resolver regex captures BOTH an old-format
# in-flight ID and a new random-token ID.
# ---------------------------------------------------------------------------

_RESOLVER_RE = _re.compile(r"\[SFID-([A-Za-z0-9-]+)\]")


def test_b3_resolver_regex_captures_old_format():
    m = _RESOLVER_RE.search("Re: [SFID-20260601-001] approval")
    assert m and m.group(1) == "20260601-001"


def test_b3_resolver_regex_captures_new_token():
    m = _RESOLVER_RE.search("Re: [SFID-20260612-cafef00d] approval")
    assert m and m.group(1) == "20260612-cafef00d"


# ---------------------------------------------------------------------------
# Change 3 — an [SFID-...] reply to an already-resolved (or unknown) request
# gets an accurate message; an awaiting_reply request falls through (None).
# ---------------------------------------------------------------------------

def test_resolved_reply_approved_says_already_applied():
    subject, body = spam_filter._resolved_sfid_reply(
        {"status": "approved", "resolution": "approved"}, "SFID-X")
    assert subject == "Re: [SFID-X]"
    assert body == "This was already applied."


def test_resolved_reply_rejected_says_already_declined():
    subject, body = spam_filter._resolved_sfid_reply(
        {"status": "rejected", "resolution": "rejected"}, "SFID-X")
    assert subject == "Re: [SFID-X]"
    assert body == "This was already declined."


def test_resolved_reply_expired_says_expired_copy():
    subject, body = spam_filter._resolved_sfid_reply(
        {"status": "expired", "resolution": None}, "SFID-X")
    assert subject == "Re: [SFID-X]"
    assert body == "This request expired, so nothing was changed."


def test_resolved_reply_none_conv_says_not_found():
    subject, body = spam_filter._resolved_sfid_reply(None, "SFID-X")
    assert subject == "Re: [SFID-X] — Not Found"
    assert body == ("We couldn't find that request. It may have been very old "
                    "or already cleared.")


def test_resolved_reply_awaiting_falls_through():
    assert spam_filter._resolved_sfid_reply(
        {"status": "awaiting_reply", "resolution": None}, "SFID-X") is None


# ---------------------------------------------------------------------------
# C2 — forward-parsing safety (Session 3)
#
# C2a: candidate collection + sender-conflict surfacing in parse_forwarded_email.
#   The chosen original_from is UNCHANGED from today (precedence is preserved).
#   What's new: _candidates (ordered) and _sender_conflict metadata so the
#   handlers can warn the owner when a forward contains more than one plausible
#   original sender (a spammer planting a fake forward block under a genuine
#   client attribution, or a From: line that belongs to a deeper nested block).
# ---------------------------------------------------------------------------

def test_c2a_fake_divider_below_real_attribution_flags_conflict():
    # A genuine client attribution ("On ... wrote:") sits at the top; a fake
    # "Begin forwarded message:" block is planted BELOW it carrying a spammer's
    # From: header. The divider wins original_from (precedence unchanged), but
    # the inline address above the divider is surfaced as a conflict.
    body = (
        "On Mon, Apr 19, 2026 at 10:00 AM, Real Person <real@client.com> wrote:\n"
        "\n"
        "Begin forwarded message:\n"
        "From: Spammer <spammer@evil.com>\n"
        "Subject: You won\n"
        "Date: Mon, 19 Apr 2026 09:00:00 -0700\n"
        "\n"
        "claim your prize\n"
    )
    fwd = spam_filter.parse_forwarded_email(body, "")
    # Precedence unchanged: the divider's From: header is original_from.
    assert parse_addr(fwd["original_from"]) == "spammer@evil.com"
    conflict = fwd.get("_sender_conflict")
    assert conflict is not None
    assert parse_addr_lower(conflict["chosen"]) == "spammer@evil.com"
    assert "real@client.com" in [a.lower() for a in conflict["others"]]


def test_c2a_normal_apple_mail_forward_no_conflict():
    # A clean Apple-Mail forward with a single sender: no conflict at all.
    body = (
        "Please block this one.\n"
        "\n"
        "Begin forwarded message:\n"
        "From: Spammer <spammer@evil.com>\n"
        "Subject: You won\n"
        "Date: Mon, 19 Apr 2026 09:00:00 -0700\n"
        "\n"
        "claim your prize\n"
    )
    fwd = spam_filter.parse_forwarded_email(body, "")
    assert parse_addr(fwd["original_from"]) == "spammer@evil.com"
    assert fwd.get("_sender_conflict") is None


def test_c2a_reply_quotes_below_divider_no_noise():
    # A real forwarded message whose forwarded CONTENT contains reply-thread
    # "On ... X wrote:" lines BELOW the divider must NOT generate a conflict.
    # Scanning below the divider for inline matches would create false alarms
    # on every legitimate forwarded reply chain.
    body = (
        "Block this please.\n"
        "\n"
        "Begin forwarded message:\n"
        "From: Spammer <spammer@evil.com>\n"
        "Subject: Re: thread\n"
        "Date: Mon, 19 Apr 2026 09:00:00 -0700\n"
        "\n"
        "Thanks!\n"
        "\n"
        "On Sun, Apr 18, 2026 at 8:00 AM, Colleague <colleague@work.com> wrote:\n"
        "> earlier message in the thread\n"
    )
    fwd = spam_filter.parse_forwarded_email(body, "")
    assert parse_addr(fwd["original_from"]) == "spammer@evil.com"
    assert fwd.get("_sender_conflict") is None


def test_c2a_from_beyond_next_divider_flagged():
    # The From: line the parser used lies BEYOND a second divider that occurs
    # after the chosen one — i.e. it belongs to a deeper nested forward block.
    # Keep today's extraction but flag the conflict with that reason.
    body = (
        "Block this.\n"
        "\n"
        "Begin forwarded message:\n"
        "Subject: outer (no From here)\n"
        "Date: Mon, 19 Apr 2026 09:00:00 -0700\n"
        "\n"
        "----- Forwarded message -----\n"
        "From: Deep Sender <deep@evil.com>\n"
        "Subject: inner\n"
        "\n"
        "inner body\n"
    )
    fwd = spam_filter.parse_forwarded_email(body, "")
    # Today's extraction is preserved: first From: match wins (the deep one).
    assert parse_addr(fwd["original_from"]) == "deep@evil.com"
    conflict = fwd.get("_sender_conflict")
    assert conflict is not None
    assert conflict["reason"] == "from-beyond-next-divider"


def test_c2a_candidates_key_present_and_ordered():
    # _candidates is additive and starts with the chosen sender.
    body = (
        "On Mon, Apr 19, 2026 at 10:00 AM, Real Person <real@client.com> wrote:\n"
        "\n"
        "Begin forwarded message:\n"
        "From: Spammer <spammer@evil.com>\n"
        "Subject: You won\n"
        "\n"
        "prize\n"
    )
    fwd = spam_filter.parse_forwarded_email(body, "")
    cands = fwd.get("_candidates")
    assert isinstance(cands, list) and cands
    assert parse_addr_lower(cands[0]["address"]) == "spammer@evil.com"
    addrs = [c["address"].lower() for c in cands]
    assert "real@client.com" in addrs


# ---------------------------------------------------------------------------
# C2b — own-identity guard for spam-sender commands (Blacklist All / Address /
# Name, SPAM Example). _resolve_spam_sender walks _candidates and skips the
# owner's own identities so MailWarden never blacklists the owner because a
# spammer disguised mail as coming from them. False Positive / Whitelist /
# Whitelist Domain / Remove-from-Blacklist are DELIBERATELY exempt.
# ---------------------------------------------------------------------------

def _account_main():
    return {"username": "main@example.com"}


def test_c2b_owner_only_candidate_refuses():
    # The only sender found is the owner's own address.
    cfg = _cfg(accounts=[{"username": "main@example.com", "enabled": True}])
    fwd = {
        "original_from": "Me <main@example.com>",
        "_candidates": [{"address": "main@example.com", "name": "Me",
                         "kind": "apple-mail"}],
    }
    res = spam_filter._resolve_spam_sender(fwd, _account_main(), cfg)
    assert res["refused"] is True
    assert res["address"] in (None, "")


def test_c2b_owner_first_spammer_deeper_resolves_spammer():
    # Owner's own address is candidate #1; a non-owner spammer is deeper.
    # The resolver skips the owner and uses the spammer, reporting the skip.
    cfg = _cfg(accounts=[{"username": "main@example.com", "enabled": True}])
    fwd = {
        "original_from": "Me <main@example.com>",
        "_candidates": [
            {"address": "main@example.com", "name": "Me", "kind": "inline"},
            {"address": "spammer@evil.com", "name": "Spammer", "kind": "apple-mail"},
        ],
    }
    res = spam_filter._resolve_spam_sender(fwd, _account_main(), cfg)
    assert res["refused"] is False
    assert res["address"] == "spammer@evil.com"
    assert "main@example.com" in [a.lower() for a in res["skipped"]]


def test_c2b_non_owner_first_used_directly():
    cfg = _cfg(accounts=[{"username": "main@example.com", "enabled": True}])
    fwd = {
        "original_from": "Spammer <spammer@evil.com>",
        "_candidates": [{"address": "spammer@evil.com", "name": "Spammer",
                         "kind": "apple-mail"}],
    }
    res = spam_filter._resolve_spam_sender(fwd, _account_main(), cfg)
    assert res["refused"] is False
    assert res["address"] == "spammer@evil.com"
    assert res["skipped"] == []


def test_c2b_false_positive_exemption_owner_address_usable():
    # The exemption is at the handler layer: parse_from_address(original_from)
    # is used directly for False Positive, so the owner's OWN address still
    # resolves to a usable address (forwarding your own self-sent mail as a
    # False Positive must keep working).
    fwd = {"original_from": "Me <main@example.com>"}
    addr = utils.parse_from_address(fwd["original_from"]).get("address")
    assert addr == "main@example.com"


# ---------------------------------------------------------------------------
# M5 — "Fwd: Re:" recognition. Once at least one Fwd:/Fw: has been stripped,
# subsequent iterations also strip a leading "Re:". A bare "Re:" with no Fwd:
# stays unrecognized (today's behavior, pinned).
# ---------------------------------------------------------------------------

def test_m5_fwd_re_blacklist_all_recognized():
    assert spam_filter.detect_email_command("Fwd: Re: Blacklist All") == "Blacklist All"


def test_m5_bare_re_blacklist_all_unrecognized():
    assert spam_filter.detect_email_command("Re: Blacklist All") is None


def test_m5_fwd_fwd_re_blacklist_address_recognized():
    assert spam_filter.detect_email_command(
        "Fwd: Fwd: Re: Blacklist Address") == "Blacklist Address"


def test_m5_strip_fwd_prefix_drops_re_after_fwd():
    assert spam_filter.strip_fwd_prefix("Fwd: Re: Blacklist All") == "Blacklist All"


def test_m5_strip_fwd_prefix_bare_re_preserved():
    assert spam_filter.strip_fwd_prefix("Re: Blacklist All") == "Re: Blacklist All"


# ---------------------------------------------------------------------------
# M6 — anchored command matching. A command pattern only matches when the next
# character after it is a word boundary (not [a-z0-9]). "Blacklist Allister"
# no longer triggers "Blacklist All", "not spammy at all" no longer triggers
# "not spam", "Whitelisting" no longer triggers "whitelist".
# ---------------------------------------------------------------------------

def test_m6_blacklist_allister_does_not_match():
    assert spam_filter.detect_email_command(
        "Blacklist Allister Group quarterly update") is None


def test_m6_not_spammy_at_all_does_not_match():
    assert spam_filter.detect_email_command("not spammy at all") is None


def test_m6_blacklist_all_period_matches():
    assert spam_filter.detect_email_command("Blacklist All.") == "Blacklist All"


def test_m6_blacklist_all_dash_suffix_matches():
    assert spam_filter.detect_email_command(
        "Blacklist All - the bank one") == "Blacklist All"


def test_m6_blacklist_all_exact_matches():
    assert spam_filter.detect_email_command("Blacklist All") == "Blacklist All"


def test_m6_whitelisting_does_not_match():
    assert spam_filter.detect_email_command("Whitelisting tips") is None


# ---------------------------------------------------------------------------
# M7 — date-fragment cleanup of inline display names. Inline attribution names
# must not absorb the trailing date fragment when the regex over-captures.
# A clean "Doe, Jane <...> wrote:" (short-inline, no date) is preserved intact.
# ---------------------------------------------------------------------------

def test_m7_primary_inline_name_strips_date_fragment():
    body = ("On Mon, Apr 19, 2026 at 10:23 AM, Jane Doe <jane@spam.com> wrote:\n"
            "> quoted text\n")
    fwd = spam_filter.parse_forwarded_email(body, "")
    parsed = utils.parse_from_address(fwd["original_from"])
    assert parsed["display_name"] == "Jane Doe"
    assert parsed["address"] == "jane@spam.com"


def test_m7_wrapped_date_inline_name_cleaned():
    # Wrapped-date variant: the date spans two lines, forcing the wrapped-date
    # DOTALL pass. The display name must still come out clean.
    body = ("On Mon, Apr 19, 2026\n"
            "at 10:23 AM, Jane Doe <jane@spam.com> wrote:\n"
            "> quoted text\n")
    fwd = spam_filter.parse_forwarded_email(body, "")
    parsed = utils.parse_from_address(fwd["original_from"])
    assert parsed["display_name"] == "Jane Doe"
    assert parsed["address"] == "jane@spam.com"


def test_m7_short_inline_comma_name_preserved():
    # Clean "Doe, Jane <...> wrote:" via short-inline (no date) must be kept.
    body = "Doe, Jane <d@x.com> wrote:\n> quoted\n"
    fwd = spam_filter.parse_forwarded_email(body, "")
    parsed = utils.parse_from_address(fwd["original_from"])
    assert parsed["display_name"] == "Doe, Jane"
    assert parsed["address"] == "d@x.com"


def test_m7_bare_address_inline_unaffected():
    body = ("On Mon, Apr 19, 2026 at 10:23 AM, noreply@automated.io wrote:\n"
            "> quoted\n")
    fwd = spam_filter.parse_forwarded_email(body, "")
    assert fwd["original_from"] == "noreply@automated.io"


def test_m7_strip_date_fragment_helper_basic():
    # Direct unit test of the helper.
    assert spam_filter._strip_date_fragment(
        "Mon, Apr 19, 2026 at 10:23 AM, Jane Doe") == "Jane Doe"
    # No date-ish prefix: unchanged.
    assert spam_filter._strip_date_fragment("Doe, Jane") == "Doe, Jane"
    # No comma at all: unchanged.
    assert spam_filter._strip_date_fragment("Jane Doe") == "Jane Doe"


# ---------------------------------------------------------------------------
# Colon-form direct commands — "Whitelist: x" / "Blacklist: x" are accepted as
# Direct Whitelist / Direct Blacklist, with or without a Fwd: prefix. Empty
# payloads fall through to the table. "Whitelist domain: x" still hits the
# Whitelist Domain table entry, not the colon branch.
# ---------------------------------------------------------------------------

def test_colon_whitelist_domain_value_is_direct_whitelist():
    assert spam_filter.detect_email_command(
        "Whitelist: domain.com") == "Direct Whitelist"


def test_colon_blacklist_address_value_is_direct_blacklist():
    assert spam_filter.detect_email_command(
        "Blacklist: bad@spam.com") == "Direct Blacklist"


def test_colon_fwd_whitelist_value_is_direct_whitelist():
    assert spam_filter.detect_email_command(
        "Fwd: Whitelist: domain.com") == "Direct Whitelist"


def test_colon_whitelist_domain_colon_still_whitelist_domain():
    # "Whitelist domain: x.com" must hit Whitelist Domain, NOT the colon branch.
    assert spam_filter.detect_email_command(
        "Whitelist domain: x.com") == "Whitelist Domain"


def test_colon_empty_payload_falls_through_to_table():
    # "Whitelist:" with no value behaves as today (table-matched "Whitelist").
    assert spam_filter.detect_email_command("Whitelist:") == "Whitelist"


def test_colon_subject_payload_reaches_parse_list_body():
    # Handler-level: the subject payload after the first colon is prepended to
    # the body before parse_list_body, so a subject-only colon command works.
    # parse_list_body accepts bare addresses and @domain entries (leading @
    # required), so the payload is written to match those forms.
    payload_line = spam_filter._subject_payload_line("Whitelist: @domain.com")
    assert payload_line == "@domain.com"
    combined = spam_filter._prepend_subject_payload(
        "Whitelist: @domain.com", "extra@body.com\n")
    parsed = spam_filter.parse_list_body(combined)
    assert "domain.com" in parsed["domains"]
    assert "extra@body.com" in parsed["addresses"]


# ---------------------------------------------------------------------------
# Hardening — the auth-rejection path records the email as processed using the
# same mechanism the success path uses, so a processed_ids reset cannot cause a
# duplicate "command not verified" notice. The normal recording at 5220 must
# not double-append the same msg_id.
# ---------------------------------------------------------------------------

def test_hardening_record_processed_appends_once():
    processed = {"ids": {"acct": []}}
    seen = set()
    spam_filter._record_processed(processed, "acct", seen, "<id-1>")
    assert "<id-1>" in seen
    assert [e[0] for e in processed["ids"]["acct"]] == ["<id-1>"]


def test_hardening_record_processed_no_double_append():
    processed = {"ids": {"acct": [["<id-1>", "2026-01-01T00:00:00"]]}}
    seen = {"<id-1>"}
    # Already recorded — must not append a second entry.
    spam_filter._record_processed(processed, "acct", seen, "<id-1>")
    assert [e[0] for e in processed["ids"]["acct"]] == ["<id-1>"]


def test_hardening_record_processed_creates_account_list():
    processed = {"ids": {}}
    seen = set()
    spam_filter._record_processed(processed, "newacct", seen, "<id-9>")
    assert [e[0] for e in processed["ids"]["newacct"]] == ["<id-9>"]


# Helpers for C2 tests — parse an original_from header to its bare address.
def parse_addr(header_value):
    return (utils.parse_from_address(header_value).get("address") or "")


def parse_addr_lower(header_value):
    a = utils.parse_from_address(header_value).get("address")
    return (a or "").lower()


# ===========================================================================
# Session 3 live-verification fixes
# ===========================================================================

# ---------------------------------------------------------------------------
# Bug 1 — colon-form "Whitelist: domain.com" must persist a bare domain.
#
# parse_list_body only accepts bare email addresses and @domain entries; a
# bare "domain.com" lands in "invalid". The fix normalizes a bare-domain
# SUBJECT payload into the @domain form parse_list_body already accepts, in
# the subject-payload seam ONLY — body parsing stays byte-identical.
#
# Persistence is asserted against the real store-apply helper the Direct
# Whitelist / Direct Blacklist handlers use (_apply_parsed_list_entries),
# so these pin actual persistence into the store dict, not a copy of it.
# ---------------------------------------------------------------------------

def _wl_store():
    return {"addresses": [], "domains": []}


def test_bug1_subject_whitelist_bare_domain_persists():
    # Subject "Whitelist: example-test.com", empty body -> the domain must end
    # up in the whitelist store's domains list (bare, @ stripped).
    raw_body = spam_filter._prepend_subject_payload(
        "Whitelist: example-test.com", "")
    parsed = spam_filter.parse_list_body(raw_body)
    store = _wl_store()
    spam_filter._apply_parsed_list_entries(store, parsed)
    assert "example-test.com" in store["domains"]
    assert parsed["invalid"] == []


def test_bug1_subject_blacklist_address_persists():
    # Subject "Blacklist: bad-actor@example-test.com" -> the ADDRESS must end
    # up in the blacklist store's addresses list (addresses are unaffected by
    # the bare-domain normalization).
    raw_body = spam_filter._prepend_subject_payload(
        "Blacklist: bad-actor@example-test.com", "")
    parsed = spam_filter.parse_list_body(raw_body)
    store = _wl_store()
    spam_filter._apply_parsed_list_entries(store, parsed)
    assert "bad-actor@example-test.com" in store["addresses"]
    assert parsed["invalid"] == []


def test_bug1_subject_blacklist_bare_domain_persists():
    # Direct Blacklist supports domain entries today (the handler iterates
    # parsed["domains"]), so the same subject-payload normalization applies:
    # "Blacklist: spammy-test.com" must persist as a bare domain.
    raw_body = spam_filter._prepend_subject_payload(
        "Blacklist: spammy-test.com", "")
    parsed = spam_filter.parse_list_body(raw_body)
    store = _wl_store()
    spam_filter._apply_parsed_list_entries(store, parsed)
    assert "spammy-test.com" in store["domains"]


def test_bug1_body_bare_domain_still_invalid_regression():
    # REGRESSION PIN: a bare domain in the BODY (not the subject payload) must
    # behave exactly as before the fix — it is NOT normalized, so it lands in
    # "invalid" and never persists. Body parsing must stay byte-identical.
    parsed = spam_filter.parse_list_body("example-test.com\n")
    assert parsed["domains"] == []
    assert parsed["addresses"] == []
    assert "example-test.com" in parsed["invalid"]


def test_bug1_body_at_domain_still_persists_regression():
    # REGRESSION PIN: the @domain BODY form keeps working unchanged, with the
    # same content as a subject command would carry.
    parsed = spam_filter.parse_list_body("@example-test.com\n")
    store = _wl_store()
    spam_filter._apply_parsed_list_entries(store, parsed)
    assert "example-test.com" in store["domains"]
    assert parsed["invalid"] == []


def test_bug1_subject_payload_only_normalizes_bare_domains():
    # A subject payload that is an address is NOT turned into a domain; a
    # payload with no dot (not a domain) is left for parse_list_body to reject.
    assert spam_filter._subject_payload_line(
        "Whitelist: user@host-test.com") == "user@host-test.com"
    assert spam_filter._subject_payload_line(
        "Whitelist: notadomain") == "notadomain"
    # Bare domain gets the @ prefix so parse_list_body routes it to domains.
    assert spam_filter._subject_payload_line(
        "Whitelist: example-test.com") == "@example-test.com"


# ---------------------------------------------------------------------------
# Bug 2 — a single msg_id must be recorded in processed_ids exactly once per
# run, even when the auth-rejection path records it and the message then falls
# through to a whitelisted/pass-through path that also records it.
# ---------------------------------------------------------------------------

def test_bug2_rejection_then_whitelist_records_once():
    # Simulate the live double-record: auth-rejection records the id, then the
    # whitelisted/pass-through path records the SAME id. Routed through
    # _record_processed, the second call is a no-op.
    processed = {"ids": {}}
    account_processed = set()
    msg_id = "<forged-1>"
    # Auth-rejection path (mark seen + record).
    spam_filter._record_processed(processed, "acct", account_processed, msg_id)
    # Whitelisted/pass-through path records the same id again.
    spam_filter._record_processed(processed, "acct", account_processed, msg_id)
    ids = [e[0] for e in processed["ids"]["acct"]]
    assert ids == [msg_id]  # exactly ONE entry


def test_bug2_two_distinct_ids_record_twice():
    # REGRESSION PIN: two DIFFERENT msg_ids still each record once -> two
    # entries. The idempotency is per-id, not a blanket suppression.
    processed = {"ids": {}}
    account_processed = set()
    spam_filter._record_processed(processed, "acct", account_processed, "<a>")
    spam_filter._record_processed(processed, "acct", account_processed, "<b>")
    ids = [e[0] for e in processed["ids"]["acct"]]
    assert ids == ["<a>", "<b>"]


# ---------------------------------------------------------------------------
# Item 3 — the False Positive handler resolves the original sender via
# parse_from_address, and must NEVER call _resolve_spam_sender (the C2b
# own-identity guard is deliberately exempt for False Positive, so forwarding
# your OWN self-sent mail as a false positive keeps working).
# ---------------------------------------------------------------------------

def test_item3_false_positive_does_not_call_resolver(monkeypatch):
    # Hard pin: if the FP path ever routes through _resolve_spam_sender, this
    # raises. The owner's own address must still resolve.
    monkeypatch.setattr(
        spam_filter, "_resolve_spam_sender",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("FP must not call resolver")))
    fwd_data = {"original_from": "Me <main@example.com>",
                "original_subject": "Receipt"}
    addr = spam_filter._resolve_false_positive_sender(fwd_data)
    assert addr == "main@example.com"


def test_item3_false_positive_resolver_handles_missing_from(monkeypatch):
    # No original_from -> empty string, still without touching the resolver.
    monkeypatch.setattr(
        spam_filter, "_resolve_spam_sender",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("FP must not call resolver")))
    assert spam_filter._resolve_false_positive_sender({}) == ""


# ---------------------------------------------------------------------------
# C5a — per-clause DKIM correlation. A header.d/header.i is only harvested as
# AUTHENTICATED from a clause whose OWN dkim= result passed. A forged
# dkim=fail clause naming a brand domain must NOT leak into proven domains.
# ---------------------------------------------------------------------------

def test_c5a_dkim_fail_domain_excluded():
    s = utils.summarize_authentication(
        {"Authentication-Results":
         "mx.google.com; dkim=fail header.d=evil.ru; dkim=pass header.d=good.com"},
        "good.com")
    assert s["authenticated_domains"] == ["good.com"]
    assert "evil.ru" not in s["authenticated_domains"]


def test_c5a_dkim_fail_first_order_variant():
    # Reversed clause order: pass clause first, fail clause second. Same result.
    s = utils.summarize_authentication(
        {"Authentication-Results":
         "mx.google.com; dkim=pass header.d=good.com; dkim=fail header.d=evil.ru"},
        "good.com")
    assert s["authenticated_domains"] == ["good.com"]
    assert "evil.ru" not in s["authenticated_domains"]


# ---------------------------------------------------------------------------
# C5b — trusted Authentication-Results selection by authserv-id, and the
# refusal of forged ARC results to grant a proven sender.
# ---------------------------------------------------------------------------

def test_c5b_selects_trusted_authserv():
    headers = [
        "mx.google.com; dkim=pass header.d=good.com",
        "evil.example; dkim=pass header.d=chase.com",
    ]
    # Anchor matches the FIRST header's authserv-id (google.com) -> that header.
    assert utils.select_trusted_auth_results(headers, {"google.com"}) == \
        "mx.google.com; dkim=pass header.d=good.com"
    # Anchor matches NO header -> trust nothing.
    assert utils.select_trusted_auth_results(headers, {"attacker.tld"}) == ""


def test_c5b_forged_arc_no_proven():
    # The verified-looking result lives ONLY in ARC-Authentication-Results and
    # claims chase.com. ARC is dropped, so chase.com must NOT be proven.
    s = utils.summarize_authentication(
        {"ARC-Authentication-Results":
         "mx.attacker; dkim=pass header.d=chase.com; "
         "dmarc=pass header.from=chase.com; spf=pass smtp.mailfrom=chase.com"},
        "chase.com")
    assert "chase.com" not in s["authenticated_domains"]
    assert s["authenticated_domains"] == []


def test_c5_dkim_signature_claim_not_proven():
    # SECURITY (audit C5): a forged DKIM-Signature d=chase.com plus a genuinely
    # passing signature for a throwaway domain must NOT make chase.com proven.
    s = utils.summarize_authentication({
        "Authentication-Results": "mx.trusted.com; dkim=pass header.d=evil.com; "
                                  "dkim=fail header.d=chase.com",
        "DKIM-Signature": "v=1; a=rsa-sha256; d=chase.com; s=sel; h=from; bh=x; b=AAAA",
    }, "chase.com")
    assert "chase.com" not in s["authenticated_domains"]
    assert "evil.com" in s["authenticated_domains"]          # the one that really passed
    assert "chase.com" in s["claimed_unverified_domains"]    # still shown to AI as unproven


# ---------------------------------------------------------------------------
# B5 — trailing-dot (FQDN root) normalization on domains/addresses.
# ---------------------------------------------------------------------------

def test_b5_trailing_dot_extract_domain():
    assert utils.extract_domain("a@spammer.com.") == "@spammer.com"


def test_b5_trailing_dot_parse_from_address():
    assert utils.parse_from_address("a@chase.com.")["address"] == "a@chase.com"


# ---------------------------------------------------------------------------
# B6 — spam_filter.parse_from delegates to the canonical parser, so a nested
# display-name spoof cannot smuggle a brand address into the email slot, and a
# display-name-only From never lands in the email slot.
# ---------------------------------------------------------------------------

def test_b6_nested_display_name_canonical():
    name, addr = spam_filter.parse_from('"Chase <svc@chase.com>" <x@evil.ru>')
    assert addr == "x@evil.ru"


def test_b6_display_name_only_not_email():
    assert spam_filter.parse_from("Marketing Team") == ("Marketing Team", "")


# ---------------------------------------------------------------------------
# M9 — connecting-IP extraction trusts only bracketed/parenthesized forms,
# skips our own relays, and rejects invalid octets.
# ---------------------------------------------------------------------------

def test_m9_bracketed_ip_chosen():
    # 8.8.8.8 is genuinely public (TEST-NET ranges are is_reserved and would be
    # skipped). A trailing HELO/date fragment must NOT be picked.
    hdr = "from mail.helo.example by mine.com (sender.example [8.8.8.8]); " \
          "Mon, 1 Jan 2024 10:20:30 +0000"
    assert utils._extract_sending_ip([hdr]) == "8.8.8.8"
    # Invalid octet -> not a valid IP -> None.
    assert utils._extract_sending_ip(["from x (host [999.1.2.3])"]) is None


def test_m9_skips_own_host_ip():
    # Topmost header's `by` is one of OUR hosts -> skipped; the real sender's
    # connecting IP from the next header is returned instead.
    hdrs = [
        "from internal by mine.com (relay [1.1.1.1])",
        "from sender.example by edge.example (sender.example [8.8.8.8])",
    ]
    assert utils._extract_sending_ip(hdrs, own_hosts={"mine.com"}) == "8.8.8.8"


# ---------------------------------------------------------------------------
# M10 — IPv6 connecting IPs are extracted; IPv6 DNSBL label construction works.
# ---------------------------------------------------------------------------

def test_m10_ipv6_extracted():
    # 2606:4700:4700::1111 is a genuinely public IPv6 (Cloudflare).
    assert utils._extract_sending_ip(
        ["from x ([IPv6:2606:4700:4700::1111])"]) == "2606:4700:4700::1111"
    # 2001:db8::/32 is the documentation range (is_reserved) -> NOT returned.
    assert utils._extract_sending_ip(["from x ([IPv6:2001:db8::1])"]) is None


def test_m10_ipv6_dnsbl_label_shape():
    # The nibble-reversed label is the reverse_pointer minus the .ip6.arpa suffix
    # (33 reversed nibbles, dot-separated). Verify the slicing locally.
    import ipaddress
    ip = ipaddress.ip_address("2606:4700:4700::1111")
    label = ip.reverse_pointer[: -len(".ip6.arpa")]
    # reverse_pointer is nibble-reversed: starts with the LAST nibble (1 from
    # ...1111) and ends with the FIRST nibble (2 from 2606...).
    assert label.startswith("1.")       # last nibble of ...1111
    assert label.endswith(".2")         # first nibble of 2606...
    assert ".ip6.arpa" not in label
    assert len(label.split(".")) == 32  # 32 nibbles for a /128 v6 address
    # check_ip_reputation must accept a v6 string and return the standard dict
    # structure without raising (network result may NXDOMAIN; structure only).
    r = utils.check_ip_reputation("2606:4700:4700::1111", timeout=0.01)
    assert set(r.keys()) == {"signal", "detail", "hits"}

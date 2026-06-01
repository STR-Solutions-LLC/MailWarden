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

import utils  # noqa: E402
import spam_filter  # noqa: E402


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

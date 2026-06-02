#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Phase 1a — "Check an Email" (Explain & Teach) screen.

Test-first coverage for the LOGIC behind the screen (the GUI itself is
verified on the M1). Two units under test:

  1. spam_filter.classify_eml_offline(..., whitelist=, blacklist=)
     — the offline classify path now also applies the user's allow/block
       lists in the SAME precedence order as the live run_filter loop, so the
       screen's answer matches what MailWarden actually does.

  2. mailwarden_app.explain_text
     — the plain-English library that turns pre-filter signal names + list
       matches + the AI result into the wording the owner approved.

Run with the test venv:
  tests/.venv/bin/python -c "import pytest; raise SystemExit(pytest.main(['tests/test_phase1a.py','-q']))"
"""
import sys
import os

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402
import learn_signals  # noqa: E402
from mailwarden_app import explain_text  # noqa: E402


SIGNALS = {"signals": {}, "ai_refinements": []}

# A normal-looking email: From/Message-ID share a domain, no auth headers,
# no Reply-To, no List-Unsubscribe, body long enough to avoid DEGRADED_PLAIN_TEXT.
# => check_header_signals fires NOTHING, so the only thing that can decide it
# is the list gate (or, with a key, the AI).
RAW_NORMAL = (
    b"From: Promo <promo@evil.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Win a prize today\r\n"
    b"Message-ID: <abc123@evil.com>\r\n"
    b"\r\n"
    b"Hello friend, this is a perfectly normal length body with plenty of real "
    b"words in it so the plain-text quality check stays quiet. Thanks for reading.\r\n"
)


def _wl(addresses=None, domains=None):
    return {"addresses": addresses or [], "domains": domains or [],
            "display_names": [], "subject_keywords": []}


def _bl(addresses=None, domains=None, display_names=None, subject_keywords=None):
    return {"addresses": addresses or [], "domains": domains or [],
            "display_names": display_names or [], "subject_keywords": subject_keywords or []}


# ---------------------------------------------------------------------------
# 1. classify_eml_offline list gate (matches live run_filter precedence)
# ---------------------------------------------------------------------------

def test_lists_whitelist_address_passes():
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(addresses=["promo@evil.com"]), blacklist=_bl())
    assert res["decided_by"] == "lists"
    assert res["final_decision"] == "PASS"
    assert res["list_match"]["kind"] == "whitelist_address"
    assert res["list_match"]["value"] == "promo@evil.com"
    assert res["ai"] is None


def test_lists_blacklist_address_junks():
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(), blacklist=_bl(addresses=["promo@evil.com"]))
    assert res["decided_by"] == "lists"
    assert res["final_decision"] == "JUNK"
    assert res["list_match"]["kind"] == "blacklist_address"


def test_lists_address_whitelist_beats_blacklist():
    # Precedence 1 (address allow) must win over the block list.
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(addresses=["promo@evil.com"]),
        blacklist=_bl(addresses=["promo@evil.com"]))
    assert res["final_decision"] == "PASS"
    assert res["list_match"]["kind"] == "whitelist_address"


def test_lists_blacklist_beats_domain_whitelist():
    # Block list (prec 2) must beat a domain allow (prec 4).
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(domains=["evil.com"]),
        blacklist=_bl(addresses=["promo@evil.com"]))
    assert res["final_decision"] == "JUNK"
    assert res["list_match"]["kind"] == "blacklist_address"


def test_lists_subject_keyword_junks():
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(), blacklist=_bl(subject_keywords=["prize"]))
    assert res["final_decision"] == "JUNK"
    assert res["list_match"]["kind"] == "subject_keyword"
    assert res["list_match"]["value"] == "prize"


def test_lists_domain_whitelist_passes():
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(domains=["evil.com"]), blacklist=_bl())
    assert res["final_decision"] == "PASS"
    assert res["list_match"]["kind"] == "whitelist_domain"


def test_lists_no_match_falls_through_to_ai():
    # Lists provided but nothing matches => normal path (no key => UNKNOWN).
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist=_wl(domains=["someone-else.com"]), blacklist=_bl())
    assert res.get("list_match") is None
    assert res["decided_by"] != "lists"


def test_backward_compatible_without_lists():
    # No whitelist/blacklist passed at all => unchanged Build-1 behavior.
    res = spam_filter.classify_eml_offline(RAW_NORMAL, SIGNALS, api_key="")
    assert res.get("list_match") is None
    assert res["decided_by"] != "lists"
    assert res["final_decision"] == "UNKNOWN"  # routed to AI, no key


def test_raw_list_dicts_need_no_precomputed_sets():
    # The screen passes raw config dicts (no _addresses_set); the function
    # must compute the lookup sets itself.
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="",
        whitelist={"addresses": ["promo@evil.com"]}, blacklist={})
    assert res["final_decision"] == "PASS"


# ---------------------------------------------------------------------------
# 2. explain_text — plain-English library (owner-approved wording)
# ---------------------------------------------------------------------------

def test_hard_signal_sentences_present_and_plain():
    s = explain_text.explain_pre_signal("SPF_DKIM_BOTH_FAIL")
    assert "forg" in s.lower()              # "forged"
    assert "SPF" not in s and "DKIM" not in s  # no jargon in the headline
    assert explain_text.explain_pre_signal("LEAKED_AI_PROMPT")
    assert "hidden command" in explain_text.explain_pre_signal("PROMPT_INJECTION_HARD").lower()
    assert "several public lists" in explain_text.explain_pre_signal("IP_DNSBL_MULTIPLE").lower()


def test_pre_signal_is_hard_classification():
    assert explain_text.pre_signal_is_hard("LEAKED_AI_PROMPT") is True
    assert explain_text.pre_signal_is_hard("PROMPT_INJECTION_HARD") is True
    assert explain_text.pre_signal_is_hard("IP_DNSBL_MULTIPLE") is True
    assert explain_text.pre_signal_is_hard("SPF_DKIM_BOTH_FAIL") is True
    assert explain_text.pre_signal_is_hard("REPLY_TO_MISMATCH") is False
    assert explain_text.pre_signal_is_hard("IP_DNSBL_SINGLE") is False


def test_reply_to_mismatch_fills_real_domains():
    detail = "Reply-To domain 'scammer.com' differs from From domain 'realbank.com'"
    s = explain_text.explain_pre_signal("REPLY_TO_MISMATCH", detail)
    assert "scammer.com" in s and "realbank.com" in s


def test_message_id_mismatch_fills_real_domains():
    detail = "Message-ID domain 'tracking.net' differs from From domain 'sender.com'"
    s = explain_text.explain_pre_signal("MESSAGE_ID_MISMATCH", detail)
    assert "tracking.net" in s and "sender.com" in s


def test_unknown_signal_is_graceful():
    s = explain_text.explain_pre_signal("SOME_FUTURE_SIGNAL", "raw detail")
    assert isinstance(s, str) and s  # non-empty, never crashes


def test_injection_pair_collapses_to_one_line():
    out = explain_text.explain_pre_signals(
        hard_signals=[],
        soft_signals=["PROMPT_INJECTION_ATTEMPT", "PROMPT_INJECTION_ATTEMPT_BOOST"],
        signal_details={"PROMPT_INJECTION_ATTEMPT": "x", "PROMPT_INJECTION_ATTEMPT_BOOST": "x"},
    )
    assert out["blocked"] == []
    assert len(out["noticed"]) == 1


def test_explain_pre_signals_splits_blocked_vs_noticed():
    out = explain_text.explain_pre_signals(
        hard_signals=["SPF_DKIM_BOTH_FAIL"],
        soft_signals=["REPLY_TO_MISMATCH"],
        signal_details={"REPLY_TO_MISMATCH": "Reply-To domain 'a.com' differs from From domain 'b.com'"},
    )
    assert len(out["blocked"]) == 1
    assert len(out["noticed"]) == 1
    assert "a.com" in out["noticed"][0]


def test_list_match_sentences():
    assert "allow" in explain_text.explain_list_match(
        {"kind": "whitelist_address", "value": "a@b.com"}).lower()
    s = explain_text.explain_list_match({"kind": "blacklist_domain", "value": "evil.com"})
    assert "evil.com" in s and "block" in s.lower()
    assert "'prize'" in explain_text.explain_list_match(
        {"kind": "subject_keyword", "value": "prize"})


def test_ai_outcome_borderline_pass():
    out = explain_text.explain_ai_outcome(
        {"decision": "SPAM", "confidence": 0.60, "signals_hit": [], "reasoning": "Looks pushy."},
        final_decision="PASS", threshold=0.85)
    assert "wasn't sure enough" in out["headline"].lower() or "below" in out["headline"].lower()
    assert out["why"] == "Looks pushy."


def test_ai_outcome_confident_junk_and_normal():
    junk = explain_text.explain_ai_outcome(
        {"decision": "SPAM", "confidence": 0.97, "signals_hit": [], "reasoning": "Phish."},
        final_decision="JUNK", threshold=0.85)
    assert "97" in junk["headline"]
    normal = explain_text.explain_ai_outcome(
        {"decision": "NOT_SPAM", "confidence": 0.9, "signals_hit": [], "reasoning": "Fine."},
        final_decision="PASS", threshold=0.85)
    assert "normal message" in normal["headline"].lower()


def test_ai_outcome_no_key_and_error():
    nk = explain_text.explain_ai_outcome({"error": "no_api_key"}, "UNKNOWN", 0.85)
    assert "api key" in nk["headline"].lower()
    err = explain_text.explain_ai_outcome({"error": "classification_failed"}, "UNKNOWN", 0.85)
    assert err["headline"]


def test_looks_like_email():
    assert explain_text.looks_like_email(RAW_NORMAL) is True
    assert explain_text.looks_like_email("just some pasted text, no headers at all") is False


def test_raw_source_help_is_comprehensive():
    h = explain_text.RAW_SOURCE_HELP
    for client in ("Gmail", "Apple Mail", "Outlook", "Yahoo", "AOL", "Thunderbird"):
        assert client in h


# ---------------------------------------------------------------------------
# 3. Real, generalized learning — both directions, generalizability-judging,
#    decline path, and legitimate-rule rendering in the classifier prompt.
# ---------------------------------------------------------------------------

def test_classifier_prompt_renders_legitimate_refinement():
    signals = {"signals": {}, "ai_refinements": [
        {"id": "R1", "status": "active", "verdict": "legitimate",
         "headline": "Newsletters from acme.com the user subscribed to",
         "rationale": "User confirmed they signed up."}]}
    out = spam_filter.build_classifier_prompt(signals, account_name=None)
    assert "LEARNED LEGITIMATE PATTERN" in out
    assert "Newsletters from acme.com" in out


def test_classifier_prompt_spam_refinement_unchanged():
    signals = {"signals": {}, "ai_refinements": [
        {"id": "R2", "status": "active",   # no verdict -> spam default (back-compat)
         "headline": "Countdown pressure from unknown retailer",
         "rationale": "Uses fake urgency."}]}
    out = spam_filter.build_classifier_prompt(signals, account_name=None)
    assert "LEARNED REFINEMENT" in out
    assert "Countdown pressure from unknown retailer" in out
    assert "LEARNED LEGITIMATE PATTERN" not in out


def test_classifier_prompt_legit_is_conditional_on_auth():
    # A legitimate rule must NOT be an absolute whitelist — it must stay
    # conditional so a later phishing look-alike isn't rescued by it.
    signals = {"signals": {}, "ai_refinements": [
        {"id": "R3", "status": "active", "verdict": "legitimate",
         "headline": "HL", "rationale": "RT"}]}
    out = spam_filter.build_classifier_prompt(signals)
    line = [l for l in out.splitlines() if "LEARNED LEGITIMATE PATTERN" in l][0]
    assert "unless" in line.lower()


def _teach_ex(reason=""):
    return {"filename": "pasted.eml", "from": "Brand <hi@brand.com>",
            "subject": "Your receipt", "received_headers": [],
            "plain_text_body": "Thanks for your order.", "user_explanation": reason}


def test_teach_prompt_spam_direction_offers_decline():
    p = learn_signals.build_teach_prompt(_teach_ex(), direction="spam",
                                         active_refinements=[])
    assert "spam" in p.lower()
    assert "no_rule" in p                # decline path is offered
    assert "<untrusted_email>" in p      # email is wrapped as untrusted data


def test_teach_prompt_legit_direction_hints_domain_and_declines():
    p = learn_signals.build_teach_prompt(_teach_ex(), direction="legitimate",
                                         active_refinements=[])
    assert "legitimate" in p.lower()
    assert "no_rule" in p
    assert "domain" in p.lower()         # the common valid generalization


def test_teach_prompt_user_reason_is_guidance_and_critiqued():
    p = learn_signals.build_teach_prompt(_teach_ex("it looks creepy"),
                                         direction="spam", active_refinements=[])
    assert "it looks creepy" in p
    assert "<user_explanation>" in p
    assert "generaliz" in p.lower()      # instruction to judge generalizability


def test_teaching_refinement_builds_scoped_legit_rule():
    cls = {"kind": "new_pattern", "headline": "HL", "rationale": "RT",
           "what_this_doesnt_cover": "WC", "confidence": "medium"}
    r = learn_signals.teaching_refinement_from_classification(
        cls, verdict="legitimate", scope=["a@b.com"],
        refinement_id="R-T-1", evidence_name="pasted.eml")
    assert r["verdict"] == "legitimate"
    assert r["scope"] == ["a@b.com"]
    assert r["headline"] == "HL"
    assert r["status"] == "proposed"
    assert r["id"] == "R-T-1"


def test_teaching_refinement_declines_no_rule():
    out = learn_signals.teaching_refinement_from_classification(
        {"kind": "no_rule", "reason": "vague"}, verdict="spam",
        scope="all", refinement_id="R", evidence_name="x")
    assert out is None


def test_teaching_refinement_spam_default():
    r = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R"},
        verdict="spam", scope="all", refinement_id="R1", evidence_name="e")
    assert r["verdict"] == "spam"
    assert r["scope"] == "all"


def test_call_claude_accepts_system_override():
    import inspect
    assert "system" in inspect.signature(learn_signals.call_claude).parameters

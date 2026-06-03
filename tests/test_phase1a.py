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
# no hard-signal tells. => check_header_signals fires NOTHING, so the only thing
# that can decide it is the list gate (or, with a key, the AI).
RAW_NORMAL = (
    b"From: Promo <promo@evil.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Win a prize today\r\n"
    b"Message-ID: <abc123@evil.com>\r\n"
    b"\r\n"
    b"Hello friend, this is a perfectly normal length body with plenty of real "
    b"words in it. Thanks for reading.\r\n"
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
    # Every remaining pre-filter signal is HARD; non-signals are not hard.
    assert explain_text.pre_signal_is_hard("LEAKED_AI_PROMPT") is True
    assert explain_text.pre_signal_is_hard("PROMPT_INJECTION_HARD") is True
    assert explain_text.pre_signal_is_hard("IP_DNSBL_MULTIPLE") is True
    assert explain_text.pre_signal_is_hard("SPF_DKIM_BOTH_FAIL") is True
    assert explain_text.pre_signal_is_hard("SOME_FUTURE_SIGNAL") is False


def test_unknown_signal_is_graceful():
    s = explain_text.explain_pre_signal("SOME_FUTURE_SIGNAL", "raw detail")
    assert isinstance(s, str) and s  # non-empty, never crashes


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
    assert "LEARNED THREAT PATTERN" in out  # relabeled from "LEARNED REFINEMENT"
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


def test_teach_prompt_legit_direction_no_domain_default_steer():
    # The learner must NO LONGER push "the sender's organizational DOMAIN" as the
    # default legitimate generalization; it should ask for a content-based rule
    # and still offer the decline path.
    p = learn_signals.build_teach_prompt(_teach_ex(), direction="legitimate",
                                         active_refinements=[])
    assert "legitimate" in p.lower()
    assert "no_rule" in p
    # The removed steer phrasings must be absent from the rendered prompt.
    assert "organizational domain" not in p.lower()
    assert "most common valid generalization" not in p.lower()
    # And the new content-based guidance must be present.
    assert "content-based" in p.lower()


def test_teach_prompt_invites_conditional_content_rules():
    # Both directions should invite SUBTLE, conditional, content-based rules
    # (not bare single-domain whitelists).
    legit = learn_signals.build_teach_prompt(_teach_ex(), direction="legitimate",
                                             active_refinements=[])
    spam = learn_signals.build_teach_prompt(_teach_ex(), direction="spam",
                                            active_refinements=[])
    # Spam side explicitly invites conditional + fine distinctions (the political
    # affiliation example is the canonical subtle case).
    assert "conditional" in spam.lower() or "unless" in spam.lower()
    assert "affiliation" in spam.lower() or "party" in spam.lower()
    # Legit side invites a conditional carve-out and warns off bare whitelists.
    assert "except when" in legit.lower()
    assert "single-domain whitelist" in legit.lower()


def test_teach_prompt_user_reason_is_guidance_and_critiqued():
    # A vague, subjective reason must still be flagged as ignorable so the model
    # takes the decline path rather than minting a junk rule from it.
    p = learn_signals.build_teach_prompt(_teach_ex("it looks creepy"),
                                         direction="spam", active_refinements=[])
    assert "it looks creepy" in p
    assert "<user_explanation>" in p
    assert "generaliz" in p.lower()      # instruction to judge generalizability
    assert "no_rule" in p                # the decline path is still offered
    # The vague example is still named as something to IGNORE.
    assert "creepy" in p.lower() and "ignore" in p.lower()


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


# ---------------------------------------------------------------------------
# 3b. protect vs. curate classification (rule_class) — schema, prompt, and the
#     refinement record produced by the Check-an-Email teaching path.
# ---------------------------------------------------------------------------

def test_teach_prompt_spam_offers_rule_class_and_apply_scope():
    # The SPAM-direction prompt must ask the model to classify protect vs. curate
    # and to parse the owner's scope words; the LEGITIMATE prompt must not (a
    # legitimate rule is neither protect nor curate).
    spam = learn_signals.build_teach_prompt(_teach_ex(), direction="spam",
                                            active_refinements=[])
    assert "rule_class" in spam
    assert "protect" in spam and "curate" in spam
    assert "apply_scope" in spam
    legit = learn_signals.build_teach_prompt(_teach_ex(), direction="legitimate",
                                             active_refinements=[])
    assert "rule_class" not in legit
    assert "apply_scope" not in legit


def test_teach_system_defines_protect_and_curate():
    sysp = learn_signals.TEACH_SYSTEM
    assert "protect" in sysp and "curate" in sysp
    # protect = bad-actor threat; curate = owner preference about legitimate mail.
    assert "bad-actor" in sysp.lower() or "bad actor" in sysp.lower()
    assert "preference" in sysp.lower()


def test_teaching_refinement_records_rule_class_curate():
    r = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R",
         "rule_class": "curate"},
        verdict="spam", scope=["m@e.com"], refinement_id="R1", evidence_name="e")
    assert r["rule_class"] == "curate"


def test_teaching_refinement_records_rule_class_protect():
    r = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R",
         "rule_class": "protect"},
        verdict="spam", scope="all", refinement_id="R1", evidence_name="e")
    assert r["rule_class"] == "protect"


def test_teaching_refinement_malformed_rule_class_defaults_protect():
    # A missing or garbage rule_class on a spam rule must never crash and must
    # behave like today's threat rule (protect).
    r = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R",
         "rule_class": "nonsense"},
        verdict="spam", scope="all", refinement_id="R1", evidence_name="e")
    assert r["rule_class"] == "protect"
    r2 = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R"},  # absent
        verdict="spam", scope="all", refinement_id="R2", evidence_name="e")
    assert r2["rule_class"] == "protect"


def test_teaching_refinement_legitimate_has_null_rule_class():
    # A legitimate rule is NEITHER protect nor curate.
    r = learn_signals.teaching_refinement_from_classification(
        {"kind": "new_pattern", "headline": "H", "rationale": "R"},
        verdict="legitimate", scope="all", refinement_id="R1", evidence_name="e")
    assert r["rule_class"] is None


def test_resolve_scope_protect_is_global():
    assert learn_signals._resolve_scope("protect", None, "x@e.com") == "all"


def test_resolve_scope_curate_binds_to_account():
    assert learn_signals._resolve_scope("curate", None, "m@e.com") == ["m@e.com"]


def test_resolve_scope_curate_apply_all_is_global():
    assert learn_signals._resolve_scope("curate", "all", "m@e.com") == "all"


def test_resolve_scope_curate_no_account_needs_explicit():
    assert (learn_signals._resolve_scope("curate", None, None)
            is learn_signals._SCOPE_NEEDS_EXPLICIT)


def test_classifier_renders_curate_as_user_preference():
    signals = {"signals": {}, "ai_refinements": [
        {"id": "C", "status": "active", "verdict": "spam", "rule_class": "curate",
         "headline": "Republican fundraising solicitations",
         "rationale": "User is done with these."}]}
    out = spam_filter.build_classifier_prompt(signals, account_name=None)
    assert "USER PREFERENCE (curate): Republican fundraising solicitations" in out
    assert "not bad-actor spam" in out
    assert "LEARNED THREAT PATTERN" not in out


def test_classifier_renders_protect_as_threat_pattern():
    signals = {"signals": {}, "ai_refinements": [
        {"id": "P", "status": "active", "verdict": "spam", "rule_class": "protect",
         "headline": "PayPal credential phish", "rationale": "Fake login link."}]}
    out = spam_filter.build_classifier_prompt(signals, account_name=None)
    assert "LEARNED THREAT PATTERN: PayPal credential phish" in out
    assert "USER PREFERENCE" not in out


def test_base_prompt_has_whole_context_directive():
    out = spam_filter.build_classifier_prompt({"signals": {}, "ai_refinements": []})
    assert "RULE 4 — JUDGE THE WHOLE EMAIL IN CONTEXT" in out
    flat = out.lower().replace("\n", " ")
    assert "never move an authenticated" in flat
    # The directive must STRENGTHEN, not contradict: hard signals + blacklist
    # still block, and RULE 2 phishing is still caught.
    assert "still block" in flat and "rule 2 phishing" in flat


def test_call_claude_accepts_system_override():
    import inspect
    assert "system" in inspect.signature(learn_signals.call_claude).parameters


# ---------------------------------------------------------------------------
# 4. Upstream-provider spam assessment is PRESENT-ONLY and lives in the TRUSTED
#    region of the classifier user message (outside <untrusted_email>). Built
#    end-to-end through extract_email_data + build_user_message — no live API.
# ---------------------------------------------------------------------------

# The real opening delimiter is on its own line ("\n<untrusted_email>\n"); the
# word also appears in the leading instruction sentence, so split on the line.
_UNTRUSTED_OPEN = "\n<untrusted_email>\n"

_RAW_WITH_SPAM_STATUS = (
    b"From: Sender <s@example.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Quarterly update\r\n"
    b"Message-ID: <m1@example.com>\r\n"
    b"X-Spam-Status: No, score=1.4 required=5.0\r\n"
    b"X-Spam-Score: 14\r\n"            # the ×10 integer — must be ignored
    b"X-Spam-Flag: NO\r\n"
    b"\r\n"
    b"A normal body with plenty of real words for context here. Thanks.\r\n"
)

_RAW_WITHOUT_SPAM_HEADERS = (
    b"From: Sender <s@example.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Quarterly update\r\n"
    b"Message-ID: <m2@example.com>\r\n"
    b"\r\n"
    b"A normal body with plenty of real words for context here. Thanks.\r\n"
)


def test_upstream_spam_line_present_when_header_present():
    md = spam_filter.extract_email_data(_RAW_WITH_SPAM_STATUS)
    um = spam_filter.build_user_message(md)
    # Factual line, REAL decimal (1.4) not the ×10 integer (14), flag no.
    assert "Upstream provider spam assessment: score=1.4, flag=no" in um
    assert "score=14" not in um  # the ×10 misread must never resurface


def test_upstream_spam_line_in_trusted_region_not_untrusted_block():
    md = spam_filter.extract_email_data(_RAW_WITH_SPAM_STATUS)
    um = spam_filter.build_user_message(md)
    trusted, _, untrusted = um.partition(_UNTRUSTED_OPEN)
    assert "Upstream provider spam assessment" in trusted
    assert "Upstream provider spam assessment" not in untrusted


def test_no_upstream_spam_line_when_headers_absent():
    md = spam_filter.extract_email_data(_RAW_WITHOUT_SPAM_HEADERS)
    um = spam_filter.build_user_message(md)
    assert "Upstream provider spam assessment" not in um
    assert "spam assessment" not in um.lower()
    # Must NOT invent a "no score"/"unknown" claim when the header is absent.
    assert "no score" not in um.lower()
    assert "score=" not in um.lower()

"""F5 — learner attribution.

Every classification decision must be attributable, by STABLE rule ID, to the
learned rule(s) that influenced it. These tests pin:

  * the ID scheme (existing R- ids for ai_refinements; derived S- ids for the
    bare-string default signals);
  * the $0 eval gate — the shipped-defaults prompt is UNCHANGED (no ID prefixes,
    no attribution instruction) because the defaults carry zero ai_refinements,
    so the deterministic eval baseline is preserved with no API spend;
  * the additive, fail-open response field (matched_rules) and its passthrough
    through _validate_classification / the cascade rescue synthesizer;
  * the additive decisions.log `RULE IDS:` line and its safety for the existing
    log consumers;
  * the prompt-injection whitelist (a crafted email cannot forge attribution to
    an ID that was never shown to the model).
"""
import json
import logging as _logging
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("attribution_test")
_LOGGER.addHandler(_logging.NullHandler())

DEFAULTS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "resources", "defaults", "signals.json")


def _defaults():
    with open(DEFAULTS_PATH) as f:
        return json.load(f)


def _signals_with_active_refinement(**over):
    r = {
        "id": "R-20260101-abcd12",
        "status": "active",
        "verdict": "spam",
        "rule_class": "protect",
        "headline": "fake invoice PDF asking to enable macros",
        "rationale": "urges the reader to open an attachment and enable content",
        "scope": "all",
    }
    r.update(over)
    return {
        "signals": {"hard_signals": ["homoglyph substitution in subject"]},
        "ai_refinements": [r],
    }


# ── ID scheme ────────────────────────────────────────────────────────────

def test_derive_signal_id_is_deterministic_and_stable():
    a = spam_filter._derive_signal_id("hard_signal", "homoglyph subject")
    b = spam_filter._derive_signal_id("hard_signal", "homoglyph subject")
    assert a == b
    assert a.startswith("S-")
    assert len(a) == len("S-") + 8


def test_derive_signal_id_differs_by_content_and_category():
    assert spam_filter._derive_signal_id("hard_signal", "x") != \
        spam_filter._derive_signal_id("hard_signal", "y")
    assert spam_filter._derive_signal_id("hard_signal", "x") != \
        spam_filter._derive_signal_id("soft_signal", "x")


# ── $0 EVAL GATE: shipped-defaults prompt is unchanged ────────────────────

def test_defaults_prompt_has_no_attribution_tokens():
    p = spam_filter.build_classifier_prompt(_defaults(), "owner@example.test")
    assert "matched_rules" not in p
    assert "[R-" not in p
    assert "[S-" not in p
    # legacy, un-prefixed render preserved verbatim
    assert "- LEARNED HARD SIGNAL:" in p
    assert "- LEARNED SOFT SIGNAL:" in p
    assert "- Known spam infrastructure:" in p


def test_defaults_inject_no_rule_ids():
    assert spam_filter.injected_rule_ids(_defaults(), "owner@example.test") == set()


def test_empty_signals_inject_no_rule_ids():
    assert spam_filter.injected_rule_ids({"signals": {}}, None) == set()


# ── Attribution ON when a learned rule exists ─────────────────────────────

def test_active_refinement_line_is_id_prefixed():
    sig = _signals_with_active_refinement()
    p = spam_filter.build_classifier_prompt(sig, "owner@example.test")
    assert "[R-20260101-abcd12] LEARNED THREAT PATTERN:" in p


def test_attribution_instruction_present_only_with_learned_rule():
    on = spam_filter.build_classifier_prompt(
        _signals_with_active_refinement(), "owner@example.test")
    assert "matched_rules" in on
    off = spam_filter.build_classifier_prompt(_defaults(), "owner@example.test")
    assert "matched_rules" not in off


def test_default_signal_prefixed_and_attributable_when_apparatus_on():
    sig = _signals_with_active_refinement()
    ids = spam_filter.injected_rule_ids(sig, "owner@example.test")
    assert "R-20260101-abcd12" in ids
    s_id = spam_filter._derive_signal_id(
        "hard_signal", "homoglyph substitution in subject")
    assert s_id in ids
    p = spam_filter.build_classifier_prompt(sig, "owner@example.test")
    assert f"[{s_id}] LEARNED HARD SIGNAL:" in p


def test_legacy_refinement_without_id_gets_derived_fallback():
    sig = _signals_with_active_refinement()
    del sig["ai_refinements"][0]["id"]
    ids = spam_filter.injected_rule_ids(sig, "owner@example.test")
    # exactly one refinement-derived id plus the one hard-signal id
    assert any(i.startswith("S-") for i in ids)
    assert len(ids) == 2


# ── Response schema: additive, fail-open ──────────────────────────────────

def test_validate_classification_preserves_matched_rules():
    out = spam_filter._validate_classification(
        {"decision": "SPAM", "confidence": 0.9,
         "matched_rules": ["R-1", "S-2"]})
    assert out["matched_rules"] == ["R-1", "S-2"]


def test_validate_classification_absent_matched_rules_is_empty_list():
    out = spam_filter._validate_classification(
        {"decision": "NOT_SPAM", "confidence": 0.1})
    assert out["matched_rules"] == []


def test_validate_classification_non_list_matched_rules_coerced():
    out = spam_filter._validate_classification(
        {"decision": "SPAM", "confidence": 0.9, "matched_rules": "R-1"})
    assert out["matched_rules"] == []


def test_validate_classification_drops_non_string_ids():
    out = spam_filter._validate_classification(
        {"decision": "SPAM", "confidence": 0.9,
         "matched_rules": ["R-1", 7, None]})
    assert out["matched_rules"] == ["R-1"]


# ── Cascade rescue carries attribution ────────────────────────────────────

def test_rescue_result_carries_matched_rules_from_screen():
    screen = {"decision": "SPAM", "confidence": 0.9,
              "signals_hit": ["x"], "matched_rules": ["R-9"]}
    confirm = {"decision": "NOT_SPAM", "confidence": 0.8, "reasoning": "ok"}
    out = spam_filter._synthesize_rescue_result(screen, confirm, "confirm-model")
    assert out["matched_rules"] == ["R-9"]


# ── decisions.log RULE IDS line ───────────────────────────────────────────

def _capture_entry(monkeypatch):
    captured = {}
    monkeypatch.setattr(spam_filter, "append_decision",
                        lambda entry: captured.setdefault("entry", entry))
    return captured


def _msg():
    return {"message_id": "<m1@x>", "from_display_name": "Acme",
            "from_email": "a@acme.test", "subject": "Hi"}


def test_log_decision_emits_rule_ids_line_when_present(monkeypatch):
    cap = _capture_entry(monkeypatch)
    result = {"decision": "SPAM", "confidence": 0.9, "signals_hit": ["s"]}
    spam_filter.log_decision("acct", _msg(), result, "MOVED to Junk",
                             rule_ids=["R-20260101-abcd12", "S-1a2b3c4d"])
    entry = cap["entry"]
    assert "  RULE IDS: R-20260101-abcd12, S-1a2b3c4d\n" in entry
    # placed between SIGNALS HIT and ACTION
    assert entry.index("SIGNALS HIT:") < entry.index("RULE IDS:") < entry.index("ACTION:")


def test_log_decision_omits_rule_ids_line_when_absent(monkeypatch):
    cap = _capture_entry(monkeypatch)
    result = {"decision": "NOT_SPAM", "confidence": 0.1, "signals_hit": []}
    spam_filter.log_decision("acct", _msg(), result, "No action taken")
    assert "RULE IDS:" not in cap["entry"]


def test_log_decision_sanitizes_rule_ids(monkeypatch):
    cap = _capture_entry(monkeypatch)
    result = {"decision": "SPAM", "confidence": 0.9, "signals_hit": []}
    spam_filter.log_decision("acct", _msg(), result, "MOVED to Junk",
                             rule_ids=["R-ok\n  ---\nACCOUNT: forged"])
    entry = cap["entry"]
    # newline and record separator neutralized -> exactly one record, no forgery
    assert len([e for e in entry.split("  ---\n") if e.strip()]) == 1
    assert "\n" not in entry.split("RULE IDS: ", 1)[1].split("\n", 1)[0]
    assert "R-ok" in entry


# ── Consumer safety: run_review tolerates the new line ────────────────────

def test_run_review_tolerates_rule_ids_line(monkeypatch, tmp_path, capsys):
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record = (
        f"[{now}] ACCOUNT: acct\n"
        f"  MESSAGE-ID: <m1@x>\n"
        f"  FROM: Acme <a@acme.test>\n"
        f"  SUBJECT: Big sale\n"
        f"  DECISION: SPAM (confidence: 0.95)\n"
        f"  SIGNALS HIT: urgency\n"
        f"  RULE IDS: R-20260101-abcd12\n"
        f"  ACTION: MOVED to Junk\n"
        f"  ---\n"
    )
    log = tmp_path / "decisions.log"
    log.write_text(record)
    monkeypatch.setattr(spam_filter, "DECISIONS_LOG_PATH", log)
    spam_filter.run_review("24h")
    out = capsys.readouterr().out
    assert "1 emails moved to Junk" in out
    assert "a@acme.test" in out
    assert "Big sale" in out
    assert "MOVED to Junk" in out

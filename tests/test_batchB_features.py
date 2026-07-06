#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Batch B features — adaptive prompt caching (F1), owner-approved+authenticated
AI-skip (F2), and the daily-report hard-signal tripwire flag (F3).

All Anthropic calls are fully mocked; NO real API calls (including count_tokens)
are made from these tests.

Run with the test venv:
  tests/.venv/bin/python -c "import pytest; raise SystemExit(pytest.main(['tests/test_batchB_features.py','-q']))"
"""
import logging
import os
import sys
import types
from datetime import datetime

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402
import daily_report  # noqa: E402

LOG = logging.getLogger("test_batchB")
LOG.addHandler(logging.NullHandler())


# ═════════════════════════════════════════════════════════════════════════
# FEATURE 1 — adaptive prompt caching
# ═════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _clear_token_cache():
    spam_filter._reset_prompt_token_cache()
    yield
    spam_filter._reset_prompt_token_cache()


def test_min_cacheable_per_model_matches_spec():
    t = spam_filter.resolve_min_cacheable_tokens()
    # Longest-prefix match: a dated haiku id resolves to the haiku minimum.
    assert spam_filter._min_cacheable_for_model(
        "claude-haiku-4-5-20251001", t) == 4096
    assert spam_filter._min_cacheable_for_model("claude-sonnet-4-6", t) == 2048
    assert spam_filter._min_cacheable_for_model("claude-fable-5", t) == 2048
    assert spam_filter._min_cacheable_for_model("claude-sonnet-4-5", t) == 1024
    assert spam_filter._min_cacheable_for_model("claude-sonnet-3-7", t) == 1024
    assert spam_filter._min_cacheable_for_model("claude-opus-4-8", t) == 4096
    assert spam_filter._min_cacheable_for_model("claude-opus-4-5", t) == 4096


def test_unknown_model_uses_conservative_default():
    t = spam_filter.resolve_min_cacheable_tokens()
    assert spam_filter._min_cacheable_for_model("some-future-model", t) == 4096


def test_config_override_wins_per_key_and_ignores_garbage():
    t = spam_filter.resolve_min_cacheable_tokens({"min_cacheable_tokens": {
        "claude-haiku-4-5": 999,          # override an existing key
        "brand-new-model": 512,           # add a new key
        "bad": "not-an-int",              # malformed -> skipped, no crash
    }})
    assert spam_filter._min_cacheable_for_model("claude-haiku-4-5", t) == 999
    assert spam_filter._min_cacheable_for_model("brand-new-model", t) == 512
    assert "bad" not in t
    # Untouched keys keep their default.
    assert spam_filter._min_cacheable_for_model("claude-sonnet-4-6", t) == 2048


def _count_client(count_by_model=None, raise_count=False):
    """Mock client whose messages.count_tokens returns a fixed input_tokens per
    model (or raises), and records how many times it was called."""
    calls = {"count": 0}

    def _count_tokens(**kw):
        calls["count"] += 1
        if raise_count:
            raise RuntimeError("no network in tests")
        n = (count_by_model or {}).get(kw["model"], 10000)
        return types.SimpleNamespace(input_tokens=n)

    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(count_tokens=_count_tokens))
    return client, calls


def test_measurement_cached_per_model_and_prompt_hash():
    client, calls = _count_client({"m": 5000})
    a = spam_filter._measure_stable_prompt_tokens(client, "m", "PROMPT", LOG)
    b = spam_filter._measure_stable_prompt_tokens(client, "m", "PROMPT", LOG)
    assert a == b == 5000
    assert calls["count"] == 1, "same (model, prompt) must re-use the cached count"


def test_measurement_reinvalidates_when_learned_block_changes():
    client, calls = _count_client({"m": 5000})
    spam_filter._measure_stable_prompt_tokens(client, "m", "PROMPT-v1", LOG)
    spam_filter._measure_stable_prompt_tokens(client, "m", "PROMPT-v2", LOG)
    assert calls["count"] == 2, "a changed prompt (new learned block) re-measures"


def test_count_tokens_failure_falls_back_to_local_estimate():
    client, calls = _count_client(raise_count=True)
    text = "x" * 40
    n = spam_filter._measure_stable_prompt_tokens(client, "m", text, LOG)
    assert n == len(text) // 4 == 10
    assert calls["count"] == 1  # attempted once, then cached the fallback


def test_system_param_attaches_cache_control_when_at_or_above_minimum():
    client, _ = _count_client({"claude-haiku-4-5": 4096})  # exactly the minimum
    table = spam_filter.resolve_min_cacheable_tokens()
    sp = spam_filter._system_param_for_call(
        client, "claude-haiku-4-5", "SYSTEM PROMPT TEXT", table, LOG)
    assert isinstance(sp, list) and len(sp) == 1
    block = sp[0]
    assert block["type"] == "text"
    assert block["cache_control"] == {"type": "ephemeral", "ttl": "1h"}
    # Content byte-identity: the block text equals the original prompt string.
    assert block["text"] == "SYSTEM PROMPT TEXT"


def test_system_param_plain_string_when_below_minimum():
    client, _ = _count_client({"claude-haiku-4-5": 4095})  # one below minimum
    table = spam_filter.resolve_min_cacheable_tokens()
    sp = spam_filter._system_param_for_call(
        client, "claude-haiku-4-5", "SYSTEM PROMPT TEXT", table, LOG)
    assert sp == "SYSTEM PROMPT TEXT"  # unchanged plain string, no caching


class _CreateClient:
    """Mock client capturing messages.create kwargs and answering count_tokens."""

    def __init__(self, count_tokens_value):
        self.create_kwargs = None
        self._n = count_tokens_value
        self.messages = types.SimpleNamespace(
            create=self._create, count_tokens=self._count)

    def _count(self, **kw):
        return types.SimpleNamespace(input_tokens=self._n)

    def _create(self, **kw):
        self.create_kwargs = kw
        return types.SimpleNamespace(
            content=[types.SimpleNamespace(type="text", text='{}')],
            usage=types.SimpleNamespace(
                input_tokens=5, output_tokens=1,
                cache_read_input_tokens=4090, cache_creation_input_tokens=0))


def test_classify_create_sends_cached_system_block_for_large_prompt():
    client = _CreateClient(count_tokens_value=9000)  # >= 4096 haiku minimum
    table = spam_filter.resolve_min_cacheable_tokens()
    spam_filter._classify_create(
        client, "claude-haiku-4-5-20251001", 500, "BIG SYSTEM PROMPT",
        "user msg", LOG, min_cacheable_tokens=table)
    sysparam = client.create_kwargs["system"]
    assert isinstance(sysparam, list)
    assert sysparam[0]["cache_control"] == {"type": "ephemeral", "ttl": "1h"}
    assert sysparam[0]["text"] == "BIG SYSTEM PROMPT"  # byte-identical content


def test_classify_create_keeps_plain_string_for_small_prompt():
    client = _CreateClient(count_tokens_value=10)  # far below any minimum
    table = spam_filter.resolve_min_cacheable_tokens()
    spam_filter._classify_create(
        client, "claude-haiku-4-5-20251001", 500, "tiny", "user msg", LOG,
        min_cacheable_tokens=table)
    assert client.create_kwargs["system"] == "tiny"


def test_classify_create_no_real_count_tokens_when_client_lacks_it():
    # A mock client with NO count_tokens (like the cascade tests) must not
    # crash and must not attach caching for a tiny prompt (len//4 fallback).
    class _NoCount:
        def __init__(self):
            self.create_kwargs = None
            self.messages = types.SimpleNamespace(create=self._create)

        def _create(self, **kw):
            self.create_kwargs = kw
            return types.SimpleNamespace(
                content=[types.SimpleNamespace(type="text", text='{}')],
                usage=types.SimpleNamespace(input_tokens=1, output_tokens=1))

    client = _NoCount()
    spam_filter._classify_create(client, "claude-haiku-4-5", 500,
                                 "system prompt", "user", LOG)
    assert client.create_kwargs["system"] == "system prompt"


# ═════════════════════════════════════════════════════════════════════════
# FEATURE 2 — owner-approved + authenticated AI-skip gate
# ═════════════════════════════════════════════════════════════════════════

def _plain_md(from_email="news@goodnews.test", dkim_sig="", raw=None):
    md = {
        "plain_text_body": "Hello there", "html_body": "",
        "from_display_name": "Good News", "from_email": from_email,
        "reply_to": "", "subject": "Weekly update",
        "received_headers": [], "received_headers_first_3": [],
        "auth_results": "", "received_spf": "",
        "dkim_signature": dkim_sig,
        "x_spam_flag": "", "x_spam_status": "", "message_id": "<m@x>",
    }
    if raw is not None:
        md["_raw_bytes"] = raw
    return md


def _verified_md(monkeypatch, verified_domain, from_domain=None):
    """Message whose local DKIM verifies ``verified_domain``; From is
    ``from_domain`` (defaults to verified_domain)."""
    monkeypatch.setattr(spam_filter, "verify_dkim_locally",
                        lambda *a, **k: [verified_domain])
    fd = from_domain or verified_domain
    return _plain_md(from_email=f"news@{fd}",
                     dkim_sig=f"v=1; d={verified_domain}; s=sel; b=xx",
                     raw=b"RAW")


def test_skip_fires_only_when_approved_and_authenticated(monkeypatch):
    md = _verified_md(monkeypatch, "goodnews.test")
    assert spam_filter._owner_approved_authenticated_domain(
        md, {"goodnews.test"}) == "goodnews.test"


def test_skip_absent_when_approved_but_unauthenticated():
    # Approved domain, but the From merely CLAIMS it (no DKIM verification).
    md = _plain_md(from_email="news@goodnews.test")
    assert spam_filter._owner_approved_authenticated_domain(
        md, {"goodnews.test"}) == ""


def test_skip_absent_when_authenticated_but_not_approved(monkeypatch):
    md = _verified_md(monkeypatch, "goodnews.test")
    assert spam_filter._owner_approved_authenticated_domain(
        md, {"unrelated.test"}) == ""


def test_skip_absent_when_dkim_domain_misaligned(monkeypatch):
    # DKIM verifies other.test, but the sender is goodnews.test — the
    # authenticated domain does NOT align with the From domain, so even though
    # other.test is on the approved list the gate must NOT fire.
    md = _verified_md(monkeypatch, "other.test", from_domain="goodnews.test")
    assert spam_filter._owner_approved_authenticated_domain(
        md, {"other.test", "goodnews.test"}) == ""


def test_skip_absent_with_no_approved_domains(monkeypatch):
    md = _verified_md(monkeypatch, "goodnews.test")
    assert spam_filter._owner_approved_authenticated_domain(md, set()) == ""
    assert spam_filter._owner_approved_authenticated_domain(md, None) == ""


def test_skip_gate_matches_the_owner_approved_prompt_block(monkeypatch):
    # The AI-skip gate and the OWNER-APPROVED prompt block must agree: whenever
    # the gate fires, build_user_message emits the block, and vice versa.
    md = _verified_md(monkeypatch, "goodnews.test")
    approved = {"goodnews.test"}
    fires = spam_filter._owner_approved_authenticated_domain(md, approved)
    prompt = spam_filter.build_user_message(md, approved_domains=approved)
    assert bool(fires) is ("OWNER-APPROVED SENDER" in prompt) is True


def test_owner_approved_delivered_logline_parses_as_not_spam(tmp_path, monkeypatch):
    # The Feature-2 delivered log line must count as a NOT-SPAM delivery and
    # never as a junking (so existing decisions.log parsers don't break).
    log_path = tmp_path / "decisions.log"
    monkeypatch.setattr(spam_filter, "DECISIONS_LOG_PATH", log_path)
    monkeypatch.setattr(daily_report, "DECISIONS_LOG_PATH", log_path)
    md = _plain_md()
    md["message_id"] = "<approved@x>"
    result = {"decision": "NOT_SPAM", "confidence": 0.0, "signals_hit": []}
    action = ("No action taken — owner-approved + authenticated sender "
              "(goodnews.test), delivered without AI review")
    spam_filter.log_decision("acct", md, result, action)

    from datetime import timedelta
    parsed = daily_report.parse_decisions_24h(
        datetime.now() - timedelta(hours=1), datetime.now() + timedelta(hours=1))
    assert parsed["not_spam"] == 1
    assert parsed["spam_entries"] == []
    assert parsed["spam_moved"] == 0


# ═════════════════════════════════════════════════════════════════════════
# FEATURE 3 — daily-report hard-signal tripwire flag
# ═════════════════════════════════════════════════════════════════════════

def test_tripwire_reason_maps_known_signals():
    assert daily_report._tripwire_reason("SPF_DKIM_BOTH_FAIL") == \
        "failed both authentication checks"
    assert daily_report._tripwire_reason("LEAKED_AI_PROMPT") == \
        "hidden AI-prompt text in the message"
    assert daily_report._tripwire_reason(
        "PROMPT_INJECTION_HARD, IP_DNSBL_MULTIPLE") == (
        "a prompt-injection attempt in the message, "
        "sending server listed on multiple spam blocklists")


def test_tripwire_reason_falls_back_for_unmapped_signal():
    assert daily_report._tripwire_reason("SOMETHING_NEW") == "SOMETHING_NEW"
    assert daily_report._tripwire_reason("") == ""


def _spam_entry(block_source, signals, i_from):
    return {
        "time": "9:00 AM", "from": i_from, "subject": "Subj",
        "confidence": "1.00", "signals": signals, "account": "acct",
        "dry_run": False, "rule_ids": [], "block_source": block_source,
    }


def _decisions_with(entries, moved):
    return {
        "per_account": {}, "evaluated": moved, "spam_moved": moved,
        "spam_dry_run": 0, "not_spam": 0, "errors": 0, "spam_entries": entries,
    }


def _render(decisions, monkeypatch, tmp_path):
    monkeypatch.setattr(daily_report, "LEARNER_STATE_PATH",
                        tmp_path / "no_learner.json")
    config = {"accounts": [{"name": "acct"}],
              "filter": {"dry_run": False}, "signal_learner": {}}
    return daily_report.build_report_body(
        config, decisions, datetime.now(), 0, {"derived_from_examples": 0})


def test_report_flags_hard_signal_junking(monkeypatch, tmp_path):
    entries = [_spam_entry("pre_classifier", "SPF_DKIM_BOTH_FAIL",
                           "Forged <f@evil.test>")]
    body = _render(_decisions_with(entries, 1), monkeypatch, tmp_path)
    assert "[TRIPWIRE]" in body
    assert "Junked by a built-in tripwire (failed both authentication checks)" \
        in body
    assert "no AI review" in body
    assert "reply APPROVE 1 to rescue this sender" in body


def test_report_does_not_flag_ai_junking(monkeypatch, tmp_path):
    entries = [_spam_entry("ai", "BRAND_IMPERSONATION", "Spammer <s@evil.test>")]
    body = _render(_decisions_with(entries, 1), monkeypatch, tmp_path)
    assert "[TRIPWIRE]" not in body
    assert "built-in tripwire" not in body
    assert "no AI review" not in body


def test_report_flag_only_on_hard_signal_entry_in_mixed_list(monkeypatch, tmp_path):
    entries = [
        _spam_entry("ai", "BRAND_IMPERSONATION", "AI Junk <a@evil.test>"),
        _spam_entry("pre_classifier", "PROMPT_INJECTION_HARD",
                    "Tripwire Junk <t@evil.test>"),
    ]
    body = _render(_decisions_with(entries, 2), monkeypatch, tmp_path)
    assert body.count("[TRIPWIRE]") == 1
    assert body.count("built-in tripwire") == 1
    # The flag points at item 2 (the pre_classifier entry's rendered number).
    assert "reply APPROVE 2 to rescue this sender" in body

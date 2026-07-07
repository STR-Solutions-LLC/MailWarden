# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Offline approved-sender parity (Check-an-Email / --classify-eml).

classify_eml_offline already threads ``approved_domains`` into
build_classifier_prompt(approvals_active=...) and build_user_message; these
tests lock down (a) that threading end-to-end and (b) that the two offline
callers (dashboard CheckEmailTab._do_check and app_entrypoint._run_classify_eml)
LOAD approved_senders.json and PASS its normalized domain set through — the gap
the fix closed, so Check-an-Email honors RULE 0 exactly as the live filter does.
"""
import json
import logging
import os
import sys
import types

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402

SIGNALS = {"signals": {}, "ai_refinements": []}
DOMAIN = "news.example.com"

# A DKIM-authenticated EML from DOMAIN. Because classify_eml_offline calls
# extract_email_data with no own_hosts, a raw Authentication-Results header is
# never trusted through the offline path (only local DKIM verification is), so
# the message is made "cryptographically authenticated + brand-matched to
# DOMAIN" by stubbing the shared auth gate — the SAME technique the existing
# owner-approved prompt tests use (test_sender_history test 8).
RAW = (
    b"Authentication-Results: mx.example.org; dkim=pass header.d=news.example.com; "
    b"spf=pass smtp.mailfrom=news.example.com; dmarc=pass header.from=news.example.com\r\n"
    b"From: Good News <hello@news.example.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Your weekly digest\r\n"
    b"Message-ID: <wk-1@news.example.com>\r\n"
    b"\r\n"
    b"Here is your weekly digest with plenty of normal words for the body.\r\n"
)


def _force_authenticated(monkeypatch, domain=DOMAIN):
    """Treat the message as cryptographically authenticated + brand-matched to
    ``domain`` (mirrors test_sender_history's owner-approved block setup)."""
    monkeypatch.setattr(spam_filter, "is_authenticated_brand_matched",
                        lambda auth: True)
    monkeypatch.setattr(
        spam_filter, "summarize_authentication",
        lambda headers, from_domain="", locally_verified=None: {
            "spf": "pass", "dkim": "pass", "dmarc": "pass", "arc": "none",
            "from_domain": from_domain, "authenticated_domains": [domain],
            "locally_verified_domains": []})
    monkeypatch.setattr(spam_filter, "_domain_is_brand_match",
                        lambda d, ad: True)


def _capture_prompt(monkeypatch):
    """Capture the (system_prompt, user_message) the offline classify builds,
    short-circuiting the real API call."""
    captured = {}

    def _fake_once(client, system_prompt, user_message, model, max_tokens,
                   logger, site="classify", min_cacheable_tokens=None):
        captured["system"] = system_prompt
        captured["user"] = user_message
        return ({"decision": "NOT_SPAM", "confidence": 0.10,
                 "signals_hit": [], "reasoning": ""}, None)

    monkeypatch.setattr(spam_filter, "_classify_once", _fake_once)
    return captured


# ── (1) end-to-end threading through classify_eml_offline ────────────────────

def test_offline_approved_domains_yields_owner_block_and_rule0(monkeypatch):
    _force_authenticated(monkeypatch)
    captured = _capture_prompt(monkeypatch)

    spam_filter.classify_eml_offline(
        RAW, SIGNALS, api_key="k", model="claude-haiku-4-5-20251001",
        approved_domains={DOMAIN})

    assert "OWNER-APPROVED SENDER" in captured["user"]
    assert f"verified as {DOMAIN}" in captured["user"]
    # approvals_active=True splices RULE 0 into the system prompt.
    assert "RULE 0" in captured["system"]


def test_offline_no_approved_domains_omits_block_and_rule0(monkeypatch):
    _force_authenticated(monkeypatch)  # authenticated, but nothing approved

    for approved in (None, set()):
        captured = _capture_prompt(monkeypatch)
        spam_filter.classify_eml_offline(
            RAW, SIGNALS, api_key="k", model="claude-haiku-4-5-20251001",
            approved_domains=approved)
        assert "OWNER-APPROVED SENDER" not in captured["user"]
        assert "RULE 0" not in captured["system"]


# ── (2) dashboard CheckEmailTab._do_check loads + passes approved_domains ─────

def test_do_check_loads_and_passes_approved_domains(tmp_path, monkeypatch):
    from mailwarden_app import dashboard

    # Seed a real approved_senders.json and let the REAL loader normalize it.
    p = tmp_path / "approved_senders.json"
    p.write_text(json.dumps({"domains": ["News.Example.COM"]}))
    monkeypatch.setattr(spam_filter, "APPROVED_SENDERS_PATH", p)

    captured = {}

    def _fake_classify(raw, signals, **kwargs):
        captured.update(kwargs)
        return {"final_decision": "PASS", "decided_by": "ai",
                "from_email": "", "subject": "", "pre_classifier": {},
                "ai": None}

    monkeypatch.setattr(spam_filter, "classify_eml_offline", _fake_classify)

    # Minimal headless stand-in for the Tk widget: run scheduled callbacks
    # inline so any error surfaces instead of being silently dropped.
    def _boom(msg):
        raise AssertionError(f"_do_check errored: {msg}")

    fake_self = types.SimpleNamespace(
        app=types.SimpleNamespace(after=lambda delay, fn, *a: fn(*a)),
        _render_result=lambda *a, **k: None,
        _render_error=_boom,
    )

    dashboard.CheckEmailTab._do_check(fake_self, RAW)

    assert captured.get("approved_domains") == {"news.example.com"}


def test_do_check_empty_store_passes_empty_set(tmp_path, monkeypatch):
    from mailwarden_app import dashboard

    p = tmp_path / "approved_senders.json"  # does not exist -> empty set
    monkeypatch.setattr(spam_filter, "APPROVED_SENDERS_PATH", p)

    captured = {}

    def _fake_classify(raw, signals, **kwargs):
        captured.update(kwargs)
        return {"final_decision": "PASS", "decided_by": "ai",
                "from_email": "", "subject": "", "pre_classifier": {}, "ai": None}

    monkeypatch.setattr(spam_filter, "classify_eml_offline", _fake_classify)

    fake_self = types.SimpleNamespace(
        app=types.SimpleNamespace(after=lambda delay, fn, *a: fn(*a)),
        _render_result=lambda *a, **k: None,
        _render_error=lambda msg: (_ for _ in ()).throw(
            AssertionError(f"_do_check errored: {msg}")),
    )

    dashboard.CheckEmailTab._do_check(fake_self, RAW)

    assert captured.get("approved_domains") == set()

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Correctness/security audit finding 2 — IMAP and SMTP connections must
VERIFY the server certificate and hostname.

imaplib.IMAP4_SSL / smtplib.SMTP_SSL / SMTP.starttls default to an UNVERIFIED
context (PEP 476 excluded these stdlib modules), so a bare socket accepts any
certificate and hands the account password to an active MITM. Every socket in
both trees must now pass a context built by make_tls_context() —
create_default_context() (CERT_REQUIRED + check_hostname) with a certifi
fallback when the bundled python.org build ships no system CA store.

These tests never open a real socket: constructors are monkeypatched to capture
the context kwarg, and a source-level wiring guard proves NO call site was
missed. The live handshake proof (real Gmail success + bad-cert rejection) is
run out-of-band during the fix, not here.

Run with the test venv:
  tests/.venv/bin/python -m pytest tests/test_tls_verification.py -q
"""
import imaplib
import logging
import os
import re
import smtplib
import ssl
import sys
from pathlib import Path

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402
import utils  # noqa: E402
from mailwarden_app import validators  # noqa: E402

_LOG = logging.getLogger("test_tls_verification")
_LOG.addHandler(logging.NullHandler())


def _assert_verifying(ctx):
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    # A real CA store is loaded (either the system default or the certifi
    # fallback) — verification can actually succeed against a good cert.
    assert ctx.cert_store_stats().get("x509_ca", 0) > 0


# ---------------------------------------------------------------------------
# make_tls_context — both trees produce a genuinely verifying context
# ---------------------------------------------------------------------------

def test_engine_make_tls_context_is_verifying():
    _assert_verifying(utils.make_tls_context())


def test_app_make_tls_context_is_verifying():
    _assert_verifying(validators.make_tls_context())


# ---------------------------------------------------------------------------
# Engine sockets (the finding's focus — the bare launchd filter) pass a
# verifying context. Captured via monkeypatched stdlib constructors.
# ---------------------------------------------------------------------------

class _CaptureIMAP:
    captured = {}

    def __init__(self, host, port, timeout=None, ssl_context=None):
        _CaptureIMAP.captured = {"host": host, "port": port,
                                 "timeout": timeout, "ssl_context": ssl_context}

    def login(self, u, p):
        pass

    def logout(self):
        pass


class _CaptureSMTP_SSL:
    captured = {}

    def __init__(self, host, port, timeout=None, context=None):
        _CaptureSMTP_SSL.captured = {"context": context}

    def ehlo(self):
        pass

    def login(self, u, p):
        pass


class _CaptureSMTP:
    captured = {}

    def __init__(self, host, port, timeout=None):
        pass

    def ehlo(self):
        pass

    def starttls(self, context=None):
        _CaptureSMTP.captured = {"context": context}

    def login(self, u, p):
        pass


def test_connect_imap_passes_verifying_context(monkeypatch):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", _CaptureIMAP)
    spam_filter.connect_imap(
        {"imap_host": "imap.example.com", "imap_port": 993,
         "username": "u", "password": "p"}, _LOG)
    _assert_verifying(_CaptureIMAP.captured["ssl_context"])


def test_smtp_login_implicit_tls_passes_context(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP_SSL", _CaptureSMTP_SSL)
    utils.smtp_login({"host": "smtp.example.com", "port": 465,
                      "username": "u", "password": "p"})
    _assert_verifying(_CaptureSMTP_SSL.captured["context"])


def test_smtp_login_starttls_passes_context(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP", _CaptureSMTP)
    utils.smtp_login({"host": "smtp.example.com", "port": 587,
                      "username": "u", "password": "p", "use_starttls": True})
    _assert_verifying(_CaptureSMTP.captured["context"])


def test_validators_test_imap_passes_context(monkeypatch):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", _CaptureIMAP)
    # Login raises so the function returns early after the (captured) connect —
    # we only care that the socket was built with a verifying context.
    monkeypatch.setattr(_CaptureIMAP, "login",
                        lambda self, u, p: (_ for _ in ()).throw(
                            imaplib.IMAP4.error("auth")))
    validators.test_imap("imap.example.com", 993, "u", "p")
    _assert_verifying(_CaptureIMAP.captured["ssl_context"])


def test_validators_safe_smtp_connect_passes_context(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP_SSL", _CaptureSMTP_SSL)
    validators.safe_smtp_connect("smtp.example.com", 465, "u", "p")
    _assert_verifying(_CaptureSMTP_SSL.captured["context"])


# ---------------------------------------------------------------------------
# Source-level wiring guard: NO IMAP/SMTP socket in either tree may be
# constructed without a verifying context (regression guard for future sites).
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parent.parent
_SOCKET_FILES = [
    _REPO / "payload" / "MailWarden" / "src" / "utils.py",
    _REPO / "payload" / "MailWarden" / "src" / "spam_filter.py",
    _REPO / "app" / "mailwarden_app" / "validators.py",
    _REPO / "app" / "mailwarden_app" / "setup_assistant.py",
    _REPO / "app" / "mailwarden_app" / "dashboard.py",
]


def _calls(src: str, needle: str):
    """Yield the balanced argument text of every `needle(` call in src."""
    idx = 0
    tok = needle + "("
    while True:
        i = src.find(tok, idx)
        if i == -1:
            return
        j = i + len(tok)
        depth = 1
        while j < len(src) and depth:
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
            j += 1
        yield src[i + len(tok):j - 1]
        idx = j


def test_no_socket_constructed_without_verifying_context():
    problems = []
    for path in _SOCKET_FILES:
        src = path.read_text(encoding="utf-8")
        for args in _calls(src, "IMAP4_SSL"):
            if "ssl_context" not in args:
                problems.append(f"{path.name}: IMAP4_SSL( without ssl_context")
        for args in _calls(src, "SMTP_SSL"):
            if "context" not in args:
                problems.append(f"{path.name}: SMTP_SSL( without context")
        for args in _calls(src, ".starttls"):
            if "context" not in args:
                problems.append(f"{path.name}: .starttls( without context")
    assert not problems, "unverified TLS socket(s): " + "; ".join(problems)

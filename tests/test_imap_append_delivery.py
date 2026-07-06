#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Changeset 3 — MailWarden delivers its own owner-facing mail by IMAP APPEND
(placed directly in the owner's mailbox) instead of SMTP, so it bypasses the
transit spam filters that were junking self-addressed system mail.

Guards:
  * deliver_message_imap APPENDs to INBOX WITHOUT \\Seen (unread new mail);
  * deliver_owner_mail prefers APPEND for an OWNED account (recipient == a
    configured account username), backfills Date + Message-ID, keeps the
    X-MailWarden-System stamp + threading headers, and logs the route;
  * an unowned recipient, or an APPEND failure, falls back to the stamped SMTP
    path (report never lost) and is logged;
  * spam_filter.send_email and daily_report.send_report route through it;
  * per-account report -> that account's INBOX.

No real IMAP/SMTP: the IMAP connection is faked via the utils._open_imap_for_append
seam. Report bodies come from daily_report.build_report_body — no hand-written
email bodies.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_imap_append_delivery.py -v
"""
import email
import logging
import os
import sys
from datetime import datetime
from email.mime.text import MIMEText

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import daily_report  # noqa: E402
import learn_signals  # noqa: E402
import spam_filter  # noqa: E402
import utils  # noqa: E402

_ACCT = {"name": "Main", "username": "owner@example.com",
         "imap_host": "imap.example.com", "imap_port": 993,
         "password": "secret", "enabled": True}
_CONFIG = {
    "accounts": [_ACCT],
    "smtp": {"host": "smtp.example.com", "port": 587, "username": "owner@example.com",
             "password": "secret", "from_address": "owner@example.com",
             "use_starttls": True},
    "summary": {"recipient": "owner@example.com"},
    "filter": {"dry_run": True},
    "signal_learner": {},
}


class _FakeIMAP:
    """Records APPENDs; stands in for imaplib.IMAP4_SSL. No network."""
    def __init__(self):
        self.appended = []          # (mailbox, flags, date_time, message_bytes)
        self.logged_out = False
        self.raise_on_append = False

    def append(self, mailbox, flags, date_time, message):
        if self.raise_on_append:
            raise RuntimeError("APPEND boom")
        self.appended.append((mailbox, flags, date_time, message))
        return ("OK", [b"[APPENDUID 1 2] done"])

    def logout(self):
        self.logged_out = True


@pytest.fixture
def fake_imap(monkeypatch):
    """Route utils._open_imap_for_append to a single recording FakeIMAP."""
    fake = _FakeIMAP()
    monkeypatch.setattr(utils, "_open_imap_for_append", lambda account: fake)
    return fake


def _list_logger(name):
    """A logger whose records are captured in a list for assertions."""
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    records = []

    class _H(logging.Handler):
        def emit(self, rec):
            records.append(rec)
    logger.addHandler(_H())
    logger.propagate = False
    return logger, records


# ---------------------------------------------------------------------------
# deliver_message_imap — mailbox + unread semantics
# ---------------------------------------------------------------------------

def test_append_targets_inbox_unread(fake_imap):
    logger, _ = _list_logger("t_append")
    msg = MIMEText("system body", "plain")
    msg["Subject"] = "hi"
    utils.deliver_message_imap(_ACCT, msg, logger)
    assert len(fake_imap.appended) == 1
    mailbox, flags, date_time, message = fake_imap.appended[0]
    assert mailbox == "INBOX"
    assert flags == ""              # no \Seen -> lands as UNREAD
    assert date_time is None
    assert b"system body" in message
    assert fake_imap.logged_out is True


def test_append_raises_on_non_ok(monkeypatch):
    logger, _ = _list_logger("t_append_err")

    class _BadIMAP(_FakeIMAP):
        def append(self, *a):
            return ("NO", [b"over quota"])
    monkeypatch.setattr(utils, "_open_imap_for_append", lambda account: _BadIMAP())
    with pytest.raises(RuntimeError):
        utils.deliver_message_imap(_ACCT, MIMEText("x"), logger)


# ---------------------------------------------------------------------------
# deliver_owner_mail — routing + headers + fallback
# ---------------------------------------------------------------------------

def _sent_msg_bytes(fake):
    return fake.appended[0][3]


def _parse(raw):
    """Parse appended bytes back into a message (bodies/emdash subjects are
    transfer-encoded, so compare via the parser, not raw substrings)."""
    return email.message_from_bytes(raw)


def _body(msg):
    return msg.get_payload(decode=True).decode("utf-8", "replace")


def _subject(msg):
    return str(email.header.make_header(email.header.decode_header(msg["Subject"])))


def test_owner_mail_appends_for_owned_account_with_headers(fake_imap):
    logger, _ = _list_logger("t_owner")
    smtp_called = []
    msg = MIMEText("body", "plain")
    msg["Subject"] = "Re: False Positive Analysis [SFID-1] — x"
    msg["From"] = "owner@example.com"
    msg["To"] = "owner@example.com"
    msg["X-MailWarden-System"] = "1"
    route, ok = utils.deliver_owner_mail(
        _CONFIG, msg, "owner@example.com", logger,
        lambda: smtp_called.append(True))
    assert route == "imap"
    assert ok is True
    assert smtp_called == []                 # SMTP NOT used
    raw = _sent_msg_bytes(fake_imap)
    assert b"X-MailWarden-System: 1" in raw  # stamp preserved
    assert b"Date:" in raw                   # backfilled (APPEND omits it)
    assert b"Message-ID:" in raw             # backfilled


def test_owner_mail_preserves_threading_headers(fake_imap):
    """In-Reply-To / References survive the APPEND unchanged (threading kept)."""
    logger, _ = _list_logger("t_thread")
    msg = MIMEText("body", "plain")
    msg["Subject"] = "Re: False Positive Analysis [SFID-9] — y"
    msg["From"] = "owner@example.com"
    msg["To"] = "owner@example.com"
    msg["In-Reply-To"] = "<orig-123@example.com>"
    msg["References"] = "<orig-123@example.com>"
    utils.deliver_owner_mail(_CONFIG, msg, "owner@example.com", logger,
                             lambda: None)
    raw = _sent_msg_bytes(fake_imap)
    assert b"In-Reply-To: <orig-123@example.com>" in raw
    assert b"References: <orig-123@example.com>" in raw


def test_owner_mail_falls_back_to_smtp_for_unowned_recipient(fake_imap):
    logger, _ = _list_logger("t_unowned")
    smtp_called = []
    msg = MIMEText("body", "plain")
    msg["Subject"] = "notice"
    msg["From"] = "owner@example.com"
    # external address that is NOT a configured account -> cannot APPEND
    route, ok = utils.deliver_owner_mail(
        _CONFIG, msg, "someone-else@elsewhere.test", logger,
        lambda: smtp_called.append(True) or True)
    assert route == "smtp"
    assert ok is True
    assert smtp_called == [True]
    assert fake_imap.appended == []


def test_owner_mail_append_failure_falls_back_and_logs(fake_imap):
    logger, records = _list_logger("t_fail")
    fake_imap.raise_on_append = True
    smtp_called = []
    msg = MIMEText("body", "plain")
    msg["Subject"] = "notice"
    msg["From"] = "owner@example.com"
    route, ok = utils.deliver_owner_mail(
        _CONFIG, msg, "owner@example.com", logger,
        lambda: smtp_called.append(True) or True)
    assert route == "smtp"                   # never lost
    assert ok is True
    assert smtp_called == [True]
    msgs = " ".join(r.getMessage() for r in records)
    assert "IMAP APPEND" in msgs and "SMTP fallback" in msgs   # logged the route


# ---------------------------------------------------------------------------
# send_email routes through APPEND (covers FP analysis / SFID acks / notices —
# all ~35 call sites share this one function)
# ---------------------------------------------------------------------------

def test_send_email_delivers_via_append(fake_imap):
    logger, _ = _list_logger("t_send_email")
    spam_filter.send_email(_CONFIG, "Re: False Positive Analysis [SFID-2] — z",
                           "Your false positive has been analyzed.\n",
                           logger, to_addr="owner@example.com")
    assert len(fake_imap.appended) == 1
    mailbox, flags, _dt, raw = fake_imap.appended[0]
    assert mailbox == "INBOX"
    assert flags == ""                       # unread
    parsed = _parse(raw)
    assert parsed["X-MailWarden-System"] == "1"
    assert parsed["Message-ID"] and parsed["Date"]
    assert _subject(parsed).startswith("Re: False Positive Analysis [SFID-2]")
    assert "Your false positive has been analyzed" in _body(parsed)


def test_send_email_smtp_fallback_when_recipient_not_owned(monkeypatch, fake_imap):
    logger, _ = _list_logger("t_send_email_fb")
    smtp_sent = []
    monkeypatch.setattr(utils, "smtp_login",
                        lambda cfg: _FakeSMTP(smtp_sent))
    spam_filter.send_email(_CONFIG, "notice", "body", logger,
                           to_addr="stranger@elsewhere.test")
    assert fake_imap.appended == []          # not an owned mailbox
    assert len(smtp_sent) == 1               # SMTP fallback used


class _FakeSMTP:
    def __init__(self, sink):
        self._sink = sink

    def sendmail(self, frm, to, data):
        self._sink.append((frm, to, data))

    def quit(self):
        pass


# ---------------------------------------------------------------------------
# send_report routes through APPEND, to the recipient account's INBOX
# ---------------------------------------------------------------------------

def _real_report_body(monkeypatch, tmp_path):
    monkeypatch.setattr(daily_report, "LEARNER_STATE_PATH",
                        tmp_path / "no_learner_state.json")
    return daily_report.build_report_body(
        _CONFIG, {"per_account": {}, "evaluated": 0, "spam_moved": 0,
                  "not_spam": 0, "errors": 0, "spam_entries": []},
        datetime.now(), 0, {"derived_from_examples": 0})


def test_send_report_appends_to_account_inbox(fake_imap, monkeypatch, tmp_path):
    logger, _ = _list_logger("t_report")
    body = _real_report_body(monkeypatch, tmp_path)
    daily_report.send_report(_CONFIG, "MailWarden Report [MWR-abc]", body,
                             logger, to_addr="owner@example.com")
    assert len(fake_imap.appended) == 1
    mailbox, flags, _dt, raw = fake_imap.appended[0]
    assert mailbox == "INBOX"
    assert flags == ""                       # unread
    parsed = _parse(raw)
    assert parsed["X-MailWarden-System"] == "1"   # changeset-2 stamp survives
    assert parsed["Message-ID"] and parsed["Date"]
    assert _body(parsed).startswith("SPAM FILTER DAILY REPORT")


def test_send_report_append_failure_falls_back_to_smtp(monkeypatch, tmp_path,
                                                        fake_imap):
    logger, records = _list_logger("t_report_fb")
    fake_imap.raise_on_append = True
    smtp_sent = []
    monkeypatch.setattr(utils, "smtp_login", lambda cfg: _FakeSMTP(smtp_sent))
    body = _real_report_body(monkeypatch, tmp_path)
    daily_report.send_report(_CONFIG, "MailWarden Report [MWR-xyz]", body,
                             logger, to_addr="owner@example.com")
    assert len(smtp_sent) == 1               # report never lost to APPEND failure
    msgs = " ".join(r.getMessage() for r in records)
    assert "SMTP fallback" in msgs


# ---------------------------------------------------------------------------
# learn_signals._send routes through the shared chokepoint (finding C)
# ---------------------------------------------------------------------------

def test_learner_send_routes_through_deliver_owner_mail(fake_imap):
    """The learner's _send goes through utils.deliver_owner_mail (APPEND-first),
    delivering to the owner's INBOX and returning its bool contract."""
    logger, _ = _list_logger("t_learner")
    # _send signature: (config, to_addr, subject, body, logger)
    ok = learn_signals._send(
        _CONFIG, "owner@example.com", "SPAM Example Received",
        "MailWarden analyzed your example.\n", logger)
    assert ok is True
    assert len(fake_imap.appended) == 1
    mailbox, flags, _dt, raw = fake_imap.appended[0]
    assert mailbox == "INBOX" and flags == ""
    parsed = _parse(raw)
    assert parsed["X-MailWarden-System"] == "1"
    assert parsed["Message-ID"] and parsed["Date"]


def test_learner_send_bool_reflects_smtp_fallback_failure(monkeypatch, fake_imap):
    """When APPEND is unavailable (unowned recipient) and SMTP fails, _send still
    returns False — the (route, success) tuple carries the real outcome."""
    logger, _ = _list_logger("t_learner_fail")

    class _BrokenSMTP:
        def sendmail(self, *a):
            raise RuntimeError("smtp down")

        def quit(self):
            pass
    # _send does `from utils import smtp_login` at call time -> patch utils.
    monkeypatch.setattr(utils, "smtp_login", lambda cfg: _BrokenSMTP())
    # unowned recipient -> SMTP fallback -> fails; (config, to_addr, subject, body)
    ok = learn_signals._send(
        _CONFIG, "stranger@elsewhere.test", "SPAM Example Received", "body",
        logger)
    assert ok is False
    assert fake_imap.appended == []

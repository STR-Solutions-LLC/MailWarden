#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""C5a — _expunge_one must never purge another client's \\Deleted mail.

A bare IMAP EXPUNGE purges EVERY \\Deleted message in the mailbox, including
mail another client (phone/desktop) flagged but hasn't expunged yet. The three
delete sites (move_to_junk COPY+DELETE fallback, Train-folder cleanup,
execute_spam_action delete branch) now funnel through _expunge_one, which:
  * uses UID EXPUNGE when UIDPLUS is advertised (surgical, touches nothing else);
  * without UIDPLUS, SEARCHes DELETED and bare-expunges ONLY when the sole
    \\Deleted message is our own uid — otherwise leaves it flagged + warns.
"""
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, *a, **k):
        self.warnings.append(a[0] if a else "")

    def info(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass

    def debug(self, *a, **k):
        pass


class _FakeConn:
    def __init__(self, caps=(), deleted=b"", search_status="OK"):
        self.capabilities = caps
        self._deleted = deleted           # bytes SEARCH DELETED returns
        self._search_status = search_status
        self.uid_expunge_calls = []
        self.bare_expunge_calls = 0
        self.search_calls = 0

    def uid(self, cmd, *args):
        if cmd == "EXPUNGE":
            self.uid_expunge_calls.append(args[0])
            return ("OK", [b""])
        if cmd == "SEARCH":
            self.search_calls += 1
            return (self._search_status, [self._deleted])
        return ("OK", [b""])

    def expunge(self):
        self.bare_expunge_calls += 1
        return ("OK", [b""])


def test_uidplus_uses_uid_expunge_only():
    conn = _FakeConn(caps=("IMAP4REV1", "UIDPLUS"))
    spam_filter._expunge_one(conn, b"5", _FakeLogger())
    assert conn.uid_expunge_calls == [b"5"]
    assert conn.bare_expunge_calls == 0
    assert conn.search_calls == 0          # never searches when UIDPLUS present


def test_no_uidplus_only_our_uid_deleted_bare_expunges_once():
    conn = _FakeConn(caps=("IMAP4REV1",), deleted=b"5")
    spam_filter._expunge_one(conn, b"5", _FakeLogger())
    assert conn.uid_expunge_calls == []
    assert conn.bare_expunge_calls == 1
    assert conn.search_calls == 1


def test_no_uidplus_foreign_deleted_present_leaves_flagged_and_warns():
    logger = _FakeLogger()
    conn = _FakeConn(caps=("IMAP4REV1",), deleted=b"5 9 12")  # 9,12 are foreign
    spam_filter._expunge_one(conn, b"5", logger)
    assert conn.uid_expunge_calls == []
    assert conn.bare_expunge_calls == 0    # MUST NOT purge foreign \\Deleted mail
    assert len(logger.warnings) == 1


def test_no_uidplus_search_returns_no_status_never_bare_expunges():
    # imaplib returns a "NO"/"BAD" status WITHOUT raising. With zero evidence we
    # must NOT bare-expunge (that would purge another client's \\Deleted mail on
    # a transient failure) — leave the message flagged and warn.
    logger = _FakeLogger()
    conn = _FakeConn(caps=("IMAP4REV1",), deleted=b"", search_status="NO")
    spam_filter._expunge_one(conn, b"5", logger)
    assert conn.uid_expunge_calls == []
    assert conn.bare_expunge_calls == 0
    assert len(logger.warnings) == 1

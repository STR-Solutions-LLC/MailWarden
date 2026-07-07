#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Wave-6 — HMAC-verified self-mail stamp (closes the X-MailWarden-System
spoofing hole).

Before Wave-6, ANY message bearing a bare ``X-MailWarden-System: 1`` header was
skipped by the loop-top guard, recorded processed, and left in the inbox — so a
spammer who copied that header onto real spam got a total filter bypass. The fix
requires an ``X-MailWarden-Auth: v1:HMAC_SHA256(secret, Message-ID)`` header
keyed by a per-install secret only MailWarden's own senders know.

These tests cover:
  * secret generation — idempotent, persisted, locked, fail-open;
  * the stamp header is present and correct on messages from each sender family
    driveable headlessly (engine deliver_owner_mail chokepoint; the GUI twin);
  * the engine/GUI twin HMAC helpers agree byte-for-byte;
  * the loop-top guard, driven through the real spam_filter.run_filter:
      - valid HMAC        -> skipped + recorded processed (NOT classified);
      - forged/bare header -> NOT skipped, flows to classification (the
        spoof-bypass REGRESSION test);
      - tampered Message-ID -> not skipped;
      - missing secret     -> body-marker fallback still protects marker'd mail;
  * verify never raises on garbage header values.

Harness style mirrors tests/test_fixes.py's _dry_run_filter_harness — a full
spam_filter.run_filter(force=True) drive with every IO/network call mocked.
"""
import email as _email
import json
import logging as _logging
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402
import utils  # noqa: E402

# GUI twin (separate package tree).
_APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(_APP))
from mailwarden_app import config_io  # noqa: E402

_LOGGER = _logging.getLogger("test_wave6_hmac_stamp")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"
_SECRET = "a" * 64  # a fixed hex secret for deterministic HMACs


# ═══════════════════════════════════════════════════════════════════════════
# 1. Secret generation — idempotent, persisted, locked, fail-open.
# ═══════════════════════════════════════════════════════════════════════════

def test_secret_generated_persisted_and_idempotent(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"accounts": []}))

    s1 = utils.get_or_create_self_mail_secret(cfg_path)
    assert isinstance(s1, str) and len(s1) == 64          # 32 bytes hex
    # Persisted back to the file under the "self_mail_secret" key.
    on_disk = json.loads(cfg_path.read_text())["self_mail_secret"]
    assert on_disk == s1
    # Idempotent: a second call returns the SAME secret, never a new one.
    s2 = utils.get_or_create_self_mail_secret(cfg_path)
    assert s2 == s1
    # And it did not rewrite a different value.
    assert json.loads(cfg_path.read_text())["self_mail_secret"] == s1


def test_secret_preserves_other_config_keys(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(
        {"accounts": [{"name": "A"}], "smtp": {"host": "h"}}))
    utils.get_or_create_self_mail_secret(cfg_path)
    data = json.loads(cfg_path.read_text())
    assert data["accounts"] == [{"name": "A"}]            # untouched
    assert data["smtp"] == {"host": "h"}                  # untouched
    assert "self_mail_secret" in data


def test_secret_runs_under_config_lock(tmp_path, monkeypatch):
    """The whole read-modify-write is wrapped in file_lock.locked(path) so a
    concurrent engine+GUI generation can't interleave and mint two secrets."""
    import file_lock
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"accounts": []}))
    locked_paths = []
    real_locked = file_lock.locked

    def _spy_locked(*paths, **kw):
        locked_paths.extend(paths)
        return real_locked(*paths, **kw)

    monkeypatch.setattr(file_lock, "locked", _spy_locked)
    utils.get_or_create_self_mail_secret(cfg_path)
    assert cfg_path in locked_paths


def test_secret_missing_file_returns_none(tmp_path):
    """Fail-open: no config file -> None (stamping proceeds without HMAC). Does
    NOT create the file."""
    missing = tmp_path / "does_not_exist.json"
    assert utils.get_or_create_self_mail_secret(missing) is None
    assert not missing.exists()


def test_secret_malformed_json_returns_none(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text("{not valid json")
    assert utils.get_or_create_self_mail_secret(cfg_path) is None


# ═══════════════════════════════════════════════════════════════════════════
# 2. HMAC compute / stamp / verify — pure helpers + engine⇄GUI twin parity.
# ═══════════════════════════════════════════════════════════════════════════

def test_compute_shape_and_verify_roundtrip():
    mid = "<abc.123@host.example>"
    val = utils.compute_self_mail_auth(_SECRET, mid)
    assert val.startswith("v1:")
    assert len(val) == len("v1:") + 64                    # sha256 hex digest
    assert utils.verify_self_mail_auth(val, mid, _SECRET) is True


def test_engine_and_gui_compute_are_byte_identical():
    """The engine (utils) and GUI (config_io) twins MUST produce the identical
    header value for the same (secret, message_id) — the GUI stamps what the
    engine verifies."""
    for mid in ("<x@y>", "<long.id.with.dots@sub.domain.example>", ""):
        assert utils.compute_self_mail_auth(_SECRET, mid) == \
               config_io.compute_self_mail_auth(_SECRET, mid)


def test_verify_rejects_forged_bare_and_tampered():
    mid = "<abc.123@host.example>"
    good = utils.compute_self_mail_auth(_SECRET, mid)
    # Right secret, wrong message-id (tampered) -> reject.
    assert utils.verify_self_mail_auth(good, "<other@host>", _SECRET) is False
    # Wrong secret -> reject.
    assert utils.verify_self_mail_auth(good, mid, "b" * 64) is False
    # A bare/forged value (no v1: HMAC) -> reject.
    assert utils.verify_self_mail_auth("1", mid, _SECRET) is False
    assert utils.verify_self_mail_auth("v1:deadbeef", mid, _SECRET) is False


def test_verify_never_raises_on_garbage():
    """Fail-open on ANY malformed input — never crash the tick."""
    garbage = [None, "", 123, b"bytes", "v1:", "v2:abcd", "vvvv",
               object(), ["list"], {"d": 1}]
    for g in garbage:
        # header, id, and secret each fed garbage in turn.
        assert utils.verify_self_mail_auth(g, "<m@h>", _SECRET) is False
        assert utils.verify_self_mail_auth("v1:ab", g, _SECRET) is False
        assert utils.verify_self_mail_auth("v1:ab", "<m@h>", g) is False


def test_stamp_adds_header_and_is_idempotent():
    from email.mime.text import MIMEText
    msg = MIMEText("body")
    msg["Message-ID"] = "<mid-1@host.example>"
    utils.stamp_self_mail_auth(msg, _SECRET)
    assert msg["X-MailWarden-Auth"] == \
        utils.compute_self_mail_auth(_SECRET, "<mid-1@host.example>")
    # Idempotent — a second stamp does not add a duplicate header.
    utils.stamp_self_mail_auth(msg, _SECRET)
    assert len(msg.get_all("X-MailWarden-Auth")) == 1


def test_stamp_noop_without_secret_or_message_id():
    from email.mime.text import MIMEText
    # No secret -> no header.
    m1 = MIMEText("b")
    m1["Message-ID"] = "<x@h>"
    utils.stamp_self_mail_auth(m1, None)
    assert m1.get("X-MailWarden-Auth") is None
    # No Message-ID -> no header.
    m2 = MIMEText("b")
    utils.stamp_self_mail_auth(m2, _SECRET)
    assert m2.get("X-MailWarden-Auth") is None


# ═══════════════════════════════════════════════════════════════════════════
# 3. Sender chokepoints stamp a verifiable header.
# ═══════════════════════════════════════════════════════════════════════════

def test_engine_deliver_owner_mail_stamps_verifiable_header(monkeypatch):
    """utils.deliver_owner_mail is the single engine chokepoint (send_email, the
    EULA send, daily_report.send_report and learn_signals._send all route here).
    It backfills the Message-ID then stamps a header the engine can verify."""
    from email.mime.text import MIMEText
    monkeypatch.setattr(utils, "get_or_create_self_mail_secret",
                        lambda *a, **k: _SECRET)
    sent = {}

    def _smtp_send():
        sent["msg"] = msg
        return True

    msg = MIMEText("SPAM FILTER DAILY REPORT\n...")
    msg["From"] = _ACCOUNT_KEY
    msg["Subject"] = "MailWarden report"
    # to_addr is NOT an owned account -> SMTP fallback path (no real IMAP).
    utils.deliver_owner_mail({"accounts": []}, msg, "someone@else.example",
                             _LOGGER, _smtp_send)
    mid = str(msg.get("Message-ID"))
    assert mid                                            # backfilled
    auth = msg.get("X-MailWarden-Auth")
    assert auth and utils.verify_self_mail_auth(auth, mid, _SECRET) is True


def test_gui_stamp_produces_engine_verifiable_header():
    """A GUI-stamped message (EmailMessage, as the welcome/test emails use)
    verifies under the engine's verify_self_mail_auth."""
    from email.message import EmailMessage
    import email.utils as eu
    msg = EmailMessage()
    msg["From"] = _ACCOUNT_KEY
    msg["Message-ID"] = eu.make_msgid(domain="example.com")
    config_io.stamp_self_mail_auth(msg, _SECRET)
    mid = str(msg.get("Message-ID"))
    auth = msg.get("X-MailWarden-Auth")
    assert utils.verify_self_mail_auth(auth, mid, _SECRET) is True


def test_deliver_owner_mail_no_secret_omits_header(monkeypatch):
    from email.mime.text import MIMEText
    monkeypatch.setattr(utils, "get_or_create_self_mail_secret",
                        lambda *a, **k: None)
    msg = MIMEText("body")
    msg["From"] = _ACCOUNT_KEY
    msg["Subject"] = "x"
    utils.deliver_owner_mail({"accounts": []}, msg, "x@else.example",
                             _LOGGER, lambda: True)
    assert msg.get("X-MailWarden-Auth") is None           # fail-open, no header
    assert msg.get("Message-ID")                           # still well-formed


# ═══════════════════════════════════════════════════════════════════════════
# 4. Loop-top guard — driven through the real spam_filter.run_filter.
# ═══════════════════════════════════════════════════════════════════════════

def _guard_harness(monkeypatch, *, msg_data, secret=_SECRET):
    """Drive run_filter(force=True) over ONE UNSEEN message with all IO mocked.
    Returns {"classify_email": int, "mark_uid_seen": int,
    "processed_ids": set(recorded message_ids)}."""
    calls = {"classify_email": 0, "mark_uid_seen": 0, "processed_ids": set()}

    cfg = {
        "filter": {"dry_run": False, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": _ACCOUNT_KEY,
                 "from_address": _ACCOUNT_KEY},
        "summary": {"recipient_address": _ACCOUNT_KEY},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{"name": "Acct", "enabled": True, "username": _ACCOUNT_KEY,
                      "imap_host": "imap.example.com", "junk_folder": "Junk",
                      "folders_to_scan": ["INBOX"]}],
    }

    # The Wave-6 secret run_filter loads once per tick.
    monkeypatch.setattr(spam_filter, "get_or_create_self_mail_secret",
                        lambda *a, **k: secret)

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: {"domains": [], "addresses": [],
                                        "_addresses_set": set(),
                                        "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "load_blacklist",
                        lambda logger: {"addresses": [], "domains": [],
                                        "display_names": [],
                                        "subject_keywords": []})
    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": [], "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "detect_conflicts",
                        lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage", lambda: {})
    monkeypatch.setattr(spam_filter, "new_token_delta", lambda: {})
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: {"conversations": []})
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed",
                        lambda config, logger: True)
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "scan_train_folder", lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                        lambda signals, username=None, approvals_active=False,
                        whitelist_curate_active=False: "PROMPT")
    monkeypatch.setattr(spam_filter, "log_decision", lambda *a, **k: None)

    def _capture(processed, tu, td):
        for acct, entries in processed.get("ids", {}).items():
            for e in entries:
                calls["processed_ids"].add(e[0])
    monkeypatch.setattr(spam_filter, "persist_progress", _capture)

    def _classify_spy(*a, **k):
        calls["classify_email"] += 1
        return ({"decision": "NOT SPAM", "confidence": 0.0,
                 "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify_spy)
    monkeypatch.setattr(spam_filter, "mark_uid_seen",
                        lambda *a, **k: calls.__setitem__(
                            "mark_uid_seen", calls["mark_uid_seen"] + 1))
    monkeypatch.setattr(spam_filter, "execute_spam_action",
                        lambda *a, **k: "moved")
    monkeypatch.setattr(spam_filter, "send_email", lambda *a, **k: None)

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: [b"1"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"raw")
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_data))

    spam_filter.run_filter(force=True)
    return calls


def _msg(*, message_id, auth=None, system=True, from_email="spammer@bad.example",
         subject="You won!", body="Totally normal spam body, click here."):
    """A parsed-email dict as extract_email_data returns, with a real MIME object
    carrying the requested X-MailWarden-System / X-MailWarden-Auth headers."""
    hdrs = []
    if system:
        hdrs.append("X-MailWarden-System: 1")
    if auth is not None:
        hdrs.append(f"X-MailWarden-Auth: {auth}")
    mime = _email.message_from_string("\n".join(hdrs) + "\n\n")
    return {
        "message_id": message_id, "from_email": from_email,
        "from_display_name": "Someone", "subject": subject,
        "plain_text_body": body, "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": mime,
    }


def test_valid_hmac_skipped_and_recorded(monkeypatch):
    mid = "<own-report-1@example.com>"
    auth = utils.compute_self_mail_auth(_SECRET, mid)
    calls = _guard_harness(monkeypatch,
                           msg_data=_msg(message_id=mid, auth=auth))
    assert calls["classify_email"] == 0, "verified own mail must NOT be classified"
    assert mid in calls["processed_ids"], "verified own mail must be recorded"
    assert calls["mark_uid_seen"] == 0, "own mail is left UNSEEN (finding #13)"


def test_bare_system_header_is_NOT_skipped(monkeypatch):
    """THE spoof-bypass regression test: a spammer who copies X-MailWarden-System
    onto real spam (no valid HMAC) gets NOTHING — the mail flows to normal
    classification instead of an unconditional skip."""
    mid = "<spoof-1@bad.example>"
    calls = _guard_harness(monkeypatch,
                           msg_data=_msg(message_id=mid, auth=None, system=True))
    assert calls["classify_email"] == 1, (
        "bare X-MailWarden-System (no HMAC) must NOT earn a skip — it must be "
        "classified like any other message")


def test_forged_auth_header_is_NOT_skipped(monkeypatch):
    mid = "<spoof-2@bad.example>"
    calls = _guard_harness(
        monkeypatch,
        msg_data=_msg(message_id=mid, auth="v1:" + "de" * 32, system=True))
    assert calls["classify_email"] == 1, "a forged v1: HMAC must not verify"


def test_tampered_message_id_is_NOT_skipped(monkeypatch):
    """HMAC computed over a DIFFERENT Message-ID than the one on the wire — the
    stamp no longer matches, so no skip."""
    auth_for_other = utils.compute_self_mail_auth(_SECRET, "<original@id>")
    calls = _guard_harness(
        monkeypatch,
        msg_data=_msg(message_id="<tampered@id>", auth=auth_for_other))
    assert calls["classify_email"] == 1


def test_missing_secret_body_marker_still_protects(monkeypatch):
    """Grace path (b): with NO secret, a genuinely-ours message whose body starts
    with a registered own-mail marker AND whose From is an owner identity is
    still skipped by the header-independent body-marker guard."""
    mid = "<own-report-2@example.com>"
    calls = _guard_harness(
        monkeypatch, secret=None,
        msg_data=_msg(message_id=mid, auth=None, system=True,
                      from_email=_ACCOUNT_KEY,
                      subject="Daily report",
                      body="SPAM FILTER DAILY REPORT\nsummary follows..."))
    assert calls["classify_email"] == 0, "body-marker guard must still skip"
    assert mid in calls["processed_ids"]


def test_missing_secret_spam_still_classified(monkeypatch):
    """With no secret AND no body marker AND a non-owner From, spam is classified
    (the fallback protects OUR mail, not a spammer's)."""
    calls = _guard_harness(
        monkeypatch, secret=None,
        msg_data=_msg(message_id="<spam@bad.example>", auth=None, system=True))
    assert calls["classify_email"] == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

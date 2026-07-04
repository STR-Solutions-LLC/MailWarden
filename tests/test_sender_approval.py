"""Safe sender-approval feature — approved_senders store, report APPROVE
replies, unified report numbering, and RULE 0 prompt plumbing."""
import inspect
import json
import logging as _logging
import os
import sys
import types
from datetime import datetime, timedelta

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402
import daily_report  # noqa: E402

_LOGGER = _logging.getLogger("sender_approval_test")
_LOGGER.addHandler(_logging.NullHandler())


# ═════════════════════════════════════════════════════════════════════════
# 1. approved_senders.json store round-trip
# ═════════════════════════════════════════════════════════════════════════

@pytest.fixture
def approved_path(tmp_path, monkeypatch):
    p = tmp_path / "approved_senders.json"
    monkeypatch.setattr(spam_filter, "APPROVED_SENDERS_PATH", p)
    return p


def test_store_missing_file_returns_empty(approved_path):
    data = spam_filter.load_approved_senders(_LOGGER)
    assert data["domains"] == []
    assert data["_domains_set"] == set()


def test_store_malformed_json_returns_empty(approved_path):
    approved_path.write_text("{not json!!")
    data = spam_filter.load_approved_senders(_LOGGER)
    assert data["domains"] == []
    assert data["_domains_set"] == set()


def test_store_non_object_json_returns_empty(approved_path):
    approved_path.write_text('["a.com"]')
    data = spam_filter.load_approved_senders(_LOGGER)
    assert data["domains"] == []
    assert data["_domains_set"] == set()


def test_store_add_load_normalization(approved_path):
    assert spam_filter.add_approved_domain("@News.Example.COM", _LOGGER) is True
    data = spam_filter.load_approved_senders(_LOGGER)
    assert data["domains"] == ["news.example.com"]
    assert data["_domains_set"] == {"news.example.com"}
    # Persisted file has the normalized shape + last_updated, no private keys.
    on_disk = json.loads(approved_path.read_text())
    assert on_disk["domains"] == ["news.example.com"]
    assert "last_updated" in on_disk
    assert not any(k.startswith("_") for k in on_disk)


def test_store_duplicate_add_returns_false(approved_path):
    assert spam_filter.add_approved_domain("dup.test", _LOGGER) is True
    assert spam_filter.add_approved_domain("DUP.test", _LOGGER) is False
    assert spam_filter.add_approved_domain("@dup.test", _LOGGER) is False
    data = spam_filter.load_approved_senders(_LOGGER)
    assert data["domains"] == ["dup.test"]


def test_store_empty_domain_rejected(approved_path):
    assert spam_filter.add_approved_domain("", _LOGGER) is False
    assert spam_filter.add_approved_domain("@", _LOGGER) is False
    assert spam_filter.add_approved_domain(None, _LOGGER) is False
    assert not approved_path.exists()


def test_store_no_tmp_left_behind(approved_path, tmp_path):
    spam_filter.add_approved_domain("clean.test", _LOGGER)
    leftovers = [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
    assert leftovers == []


# ═════════════════════════════════════════════════════════════════════════
# 2. parse_approve_command matrix
# ═════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("text,expected", [
    ("APPROVE 3", [3]),
    ("approve 3", [3]),
    ("Approve: 3", [3]),
    ("APPROVE 3,5", [3, 5]),
    ("APPROVE 3, 5", [3, 5]),
    ("APPROVE 3 5", [3, 5]),
    ("APPROVE 3-5", [3, 4, 5]),
    ("  approve 2  ", [2]),
    ("APPROVE 5,3,3", [3, 5]),          # de-duped, sorted
])
def test_parse_approve_forms(text, expected):
    assert spam_filter.parse_approve_command(text) == expected


@pytest.mark.parametrize("text", [
    "",
    None,
    "yes please",
    "thanks, looks good",
    "APPROVE",                            # no number
    "approve nothing",
    # The report's own instruction line: APPROVE never at line start.
    "To rescue a sender, reply to this report with APPROVE and the item "
    "number (example: APPROVE 3). MailWarden will trust mail from that "
    "sender's domain going forward. If an item was blocked by a rule you "
    "set yourself, MailWarden will reply with how to change that rule "
    "instead.",
])
def test_parse_approve_non_commands(text):
    assert spam_filter.parse_approve_command(text) == []


def test_parse_approve_with_quoted_reply_noise():
    # Owner's command on its own line above an unquoted copy of the report's
    # instruction line: only the owner's numbers parse (first line-anchored
    # match wins; the mid-line example never matches).
    text = ("APPROVE 5\n\n"
            "On Tue, Jul 1, 2026 MailWarden wrote:\n"
            "To rescue a sender, reply to this report with APPROVE and the "
            "item number (example: APPROVE 3). MailWarden will trust mail "
            "from that sender's domain going forward.")
    assert spam_filter.parse_approve_command(text) == [5]


def test_parse_approve_range_capped():
    # Runaway ranges are capped at 100 numbers.
    nums = spam_filter.parse_approve_command("APPROVE 1-99999")
    assert len(nums) == 100
    assert nums[0] == 1 and nums[-1] == 100


# ═════════════════════════════════════════════════════════════════════════
# 3. Full APPROVE-branch behavior (run_filter with all IO mocked)
# ═════════════════════════════════════════════════════════════════════════

def _mwr_msg(subject="Re: MailWarden Report — July 01, 2026 — 2 moved to Junk"
                     " [MWR-abc123]",
             body="APPROVE 1", from_email="owner@example.com"):
    return {
        "message_id": "<mwr-reply-1@example.com>",
        "from_email": from_email,
        "from_display_name": "Owner",
        "subject": subject,
        "plain_text_body": body,
        "html_body": "",
        "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "",
        "received_headers": [], "received_headers_first_3": [],
        "_mime_msg": None,
    }


def _fresh_token_store(token="abc123", entries=None):
    if entries is None:
        entries = {
            "1": {"from_domain": "newsletter.test",
                  "from": "News <n@newsletter.test>", "subject": "Weekly"},
            "2": {"from_domain": "offers.test",
                  "from": "Offers <o@offers.test>", "subject": "Deal"},
        }
    return {token: {"created": datetime.now().isoformat(),
                    "account": "Acct",
                    "window_end": datetime.now().isoformat(),
                    "entries": entries}}


def _approve_harness(monkeypatch, *, msg_data, dry_run=False,
                     sender_is_owner=True, auth_ok=True,
                     approvals_store=None, add_returns=True,
                     add_wl_returns=True, whitelist=None):
    """Drive spam_filter.run_filter(force=True) with all IO/network mocked
    (modeled on test_fixes._dry_run_filter_harness), instrumented for the
    APPROVE branch.

    ``add_wl_returns`` controls the stubbed add_whitelist_domain result
    (finding #6, Case B). ``whitelist`` overrides the default empty
    whitelist the run loads (finding #6 pre-classifier bypass tests)."""
    calls = {
        "add_approved_domain": [],
        "add_whitelist_domain": [],
        "send_email": [],           # (subject, body, to_addr)
        "notify_unverified": 0,
        "mark_uid_seen": 0,
        "classify_email": 0,
        "execute_spam_action": 0,
    }

    cfg = {
        "filter": {"dry_run": dry_run, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        # classify_mode pinned to "single": these tests stub classify_email
        # and count its calls; without the pin, run_filter's shipped-default
        # cascade would route to (unstubbed) classify_email_cascade. The
        # cascade branch has its own run_filter harness in test_cascade.py.
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": "owner@example.com",
                 "from_address": "owner@example.com"},
        "summary": {"recipient_address": "owner@example.com"},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{
            "name": "Acct", "enabled": True,
            "username": "owner@example.com",
            "imap_host": "imap.example.com",
            "junk_folder": "Junk",
            "folders_to_scan": ["INBOX"],
        }],
    }

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging",
                        lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_signals", lambda: {"signals": {}})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: (dict(whitelist) if whitelist
                                        else {"domains": [], "addresses": [],
                                              "_addresses_set": set(),
                                              "_domains_set": set()}))
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
    monkeypatch.setattr(spam_filter, "persist_progress",
                        lambda processed, tu, td: None)
    monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                        lambda signals, username=None,
                        approvals_active=False: "PROMPT")
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "prune_decisions_log", lambda: None)
    monkeypatch.setattr(spam_filter, "prune_pending_signals", lambda: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "scan_train_folder",
                        lambda conn, account, config, logger: None)
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed",
                        lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "log_decision", lambda *a, **k: None)

    monkeypatch.setattr(spam_filter, "_command_sender_is_owner",
                        lambda *a, **k: sender_is_owner)
    monkeypatch.setattr(spam_filter, "_command_auth_ok",
                        lambda *a, **k: auth_ok)

    def _notify(config, account, logger):
        calls["notify_unverified"] += 1
    monkeypatch.setattr(spam_filter, "_notify_unverified_command", _notify)

    def _add(domain, logger):
        calls["add_approved_domain"].append(domain)
        return add_returns
    monkeypatch.setattr(spam_filter, "add_approved_domain", _add)

    def _add_wl(domain, logger):
        calls["add_whitelist_domain"].append(domain)
        return add_wl_returns
    monkeypatch.setattr(spam_filter, "add_whitelist_domain", _add_wl)

    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: dict(approvals_store or {}))

    def _send(config, subject, body, logger, to_addr=None):
        calls["send_email"].append((subject, body, to_addr))
    monkeypatch.setattr(spam_filter, "send_email", _send)

    def _seen(conn, uid, logger):
        calls["mark_uid_seen"] += 1
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    def _classify(*a, **k):
        calls["classify_email"] += 1
        return ({"decision": "NOT_SPAM", "confidence": 0.0,
                 "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify)

    def _exec(*a, **k):
        calls["execute_spam_action"] += 1
        return "moved"
    monkeypatch.setattr(spam_filter, "execute_spam_action", _exec)

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


def test_branch_owner_approve_writes_domain(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 1"),
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == ["newsletter.test"]
    assert calls["mark_uid_seen"] == 1
    assert calls["classify_email"] == 0
    assert len(calls["send_email"]) == 1
    subject, body, to_addr = calls["send_email"][0]
    assert to_addr == "owner@example.com"
    assert body == ("Approved: newsletter.test (item 1). This applies "
                    "whenever a message is verified as genuinely from that "
                    "domain. Mail that can't be verified will still be "
                    "judged normally.")


def test_branch_auth_failure_writes_nothing_and_notifies(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(),
                             auth_ok=False,
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == []
    assert calls["notify_unverified"] == 1
    # Falls through to normal classification (message judged as ordinary mail).
    assert calls["classify_email"] == 1


def test_branch_non_owner_ignored(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(
                                 from_email="stranger@evil.test"),
                             sender_is_owner=False,
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == []
    assert calls["notify_unverified"] == 0
    assert calls["send_email"] == []
    # Treated as ordinary mail.
    assert calls["classify_email"] == 1


def test_branch_dry_run_defers(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(), dry_run=True,
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == []
    assert calls["send_email"] == []
    assert calls["mark_uid_seen"] == 0
    assert calls["classify_email"] == 0


def test_branch_own_report_body_never_self_triggers(monkeypatch):
    # The daily report ITSELF: [MWR-...] subject and a body containing the
    # instruction line "…(example: APPROVE 3)." — must be skipped, never
    # parsed as a command.
    report_body = ("SPAM FILTER DAILY REPORT\nJuly 01, 2026 — 8:00 AM\n\n"
                   "1. 07:01 | News <n@newsletter.test>\n\n"
                   "To rescue a sender, reply to this report with APPROVE "
                   "and the item number (example: APPROVE 3). MailWarden "
                   "will trust mail from that sender's domain going forward. "
                   "If an item was blocked by a rule you set yourself, "
                   "MailWarden will reply with how to change that rule "
                   "instead.")
    calls = _approve_harness(
        monkeypatch,
        msg_data=_mwr_msg(
            subject="MailWarden Report — July 01, 2026 — 2 moved to Junk "
                    "[MWR-abc123]",
            body=report_body),
        approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == []
    assert calls["send_email"] == []
    assert calls["classify_email"] == 0     # skipped, not classified


def test_branch_bad_number_ack(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 9"),
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("Couldn't find item 9 in that report — it listed items "
                    "1–2. No changes made.")


def test_branch_mixed_valid_and_invalid_numbers(monkeypatch):
    calls = _approve_harness(monkeypatch,
                             msg_data=_mwr_msg(body="APPROVE 1,9"),
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == ["newsletter.test"]
    subject, body, to_addr = calls["send_email"][0]
    assert "Approved: newsletter.test (item 1)." in body
    assert "Couldn't find item 9 in that report — it listed items 1–2." in body
    # Something succeeded => "No changes made." suppressed.
    assert "No changes made." not in body


def test_branch_expired_token_ack(monkeypatch):
    store = _fresh_token_store()
    store["abc123"]["created"] = (datetime.now()
                                  - timedelta(days=31)).isoformat()
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(),
                             approvals_store=store)
    assert calls["add_approved_domain"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("That report is too old for approvals. Please reply to "
                    "a more recent report.")


def test_branch_unknown_token_ack(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(),
                             approvals_store={})
    assert calls["add_approved_domain"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("That report is too old for approvals. Please reply to "
                    "a more recent report.")


def test_branch_already_approved_ack(monkeypatch):
    # add_approved_domain returning False == domain already present.
    calls = _approve_harness(monkeypatch,
                             msg_data=_mwr_msg(body="APPROVE 1"),
                             approvals_store=_fresh_token_store(),
                             add_returns=False)
    assert calls["add_approved_domain"] == ["newsletter.test"]
    subject, body, to_addr = calls["send_email"][0]
    assert body == "newsletter.test was already approved — no change."


def test_branch_multi_number_success(monkeypatch):
    calls = _approve_harness(monkeypatch,
                             msg_data=_mwr_msg(body="APPROVE 1,2"),
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == ["newsletter.test", "offers.test"]
    subject, body, to_addr = calls["send_email"][0]
    assert "Approved: newsletter.test (item 1)." in body
    assert "Approved: offers.test (item 2)." in body


def test_branch_non_approve_reply_falls_through(monkeypatch):
    calls = _approve_harness(monkeypatch,
                             msg_data=_mwr_msg(body="thanks, looks great"),
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == []
    assert calls["send_email"] == []
    assert calls["classify_email"] == 1     # ordinary mail


# ═════════════════════════════════════════════════════════════════════════
# 4. Report numbering + token map + expiry (daily_report)
# ═════════════════════════════════════════════════════════════════════════

def _decisions(moved=2, dry=2):
    entries = []
    for i in range(moved):
        entries.append({"time": f"07:0{i}", "account": "Acct",
                        "from": f"Moved{i} <m{i}@moved{i}.test>",
                        "subject": f"moved subject {i}",
                        "confidence": "0.99", "signals": "x"})
    for i in range(dry):
        entries.append({"time": f"08:0{i}", "account": "Acct",
                        "from": f"Dry{i} <d{i}@dry{i}.test>",
                        "subject": f"dry subject {i}",
                        "confidence": "0.99", "signals": "x",
                        "dry_run": True})
    return {
        "evaluated": moved + dry, "spam_moved": moved, "spam_dry_run": dry,
        "not_spam": 0, "errors": 0,
        "spam_entries": entries,
        "per_account": {"Acct": {"evaluated": moved + dry, "spam": moved,
                                 "spam_dry_run": dry, "not_spam": 0}},
    }


def _report_config():
    return {
        "filter": {"dry_run": True},
        "accounts": [{"name": "Acct", "enabled": True,
                      "username": "owner@example.com"}],
        "signal_learner": {},
    }


def test_report_unified_numbering_across_moved_and_dry_run():
    body = daily_report.build_report_body(
        _report_config(), _decisions(moved=2, dry=2), None, 0,
        {"derived_from_examples": 0})
    # Moved entries are 1..2; dry-run entries continue 3..4.
    assert "1. 07:00 | Moved0 <m0@moved0.test>" in body
    assert "2. 07:01 | Moved1 <m1@moved1.test>" in body
    assert "3. 08:00 | Dry0 <d0@dry0.test>" in body
    assert "4. 08:01 | Dry1 <d1@dry1.test>" in body
    # The dry-run list must NOT restart at 1.
    assert "1. 08:00" not in body


def test_report_rescue_copy_line_present_when_entries_exist():
    body = daily_report.build_report_body(
        _report_config(), _decisions(moved=1, dry=0), None, 0,
        {"derived_from_examples": 0})
    assert ("To rescue a sender, reply to this report with APPROVE and the "
            "item number (example: APPROVE 3). MailWarden will trust mail "
            "from that sender's domain going forward. If an item was blocked "
            "by a rule you set yourself, MailWarden will reply with how to "
            "change that rule instead.") in body


def test_report_rescue_copy_line_absent_when_no_entries():
    body = daily_report.build_report_body(
        _report_config(), _decisions(moved=0, dry=0), None, 0,
        {"derived_from_examples": 0})
    assert "To rescue a sender" not in body
    assert "No spam moved to Junk in the last 24 hours." in body


def test_report_token_map_matches_rendered_numbers():
    d = _decisions(moved=2, dry=2)
    entries = daily_report.build_approval_entries(d)
    assert set(entries.keys()) == {"1", "2", "3", "4"}
    assert entries["1"]["from_domain"] == "moved0.test"
    assert entries["2"]["from_domain"] == "moved1.test"
    assert entries["3"]["from_domain"] == "dry0.test"      # dry-run continues
    assert entries["4"]["from_domain"] == "dry1.test"
    assert entries["3"]["from"] == "Dry0 <d0@dry0.test>"
    assert entries["3"]["subject"] == "dry subject 0"


def test_report_no_entries_no_token_map():
    assert daily_report.build_approval_entries(_decisions(0, 0)) == {}


@pytest.fixture
def approvals_path(tmp_path, monkeypatch):
    p = tmp_path / "report_approvals.json"
    monkeypatch.setattr(daily_report, "REPORT_APPROVALS_PATH", p)
    return p


def test_report_two_reports_distinct_tokens_no_collision(approvals_path):
    from utils import random_token
    t1, t2 = random_token(), random_token()
    assert t1 != t2
    now = datetime.now()
    daily_report.record_report_approvals(
        t1, "Acct", now, {"1": {"from_domain": "a.test", "from": "",
                                "subject": ""}}, _LOGGER)
    daily_report.record_report_approvals(
        t2, "Acct", now, {"1": {"from_domain": "b.test", "from": "",
                                "subject": ""}}, _LOGGER)
    data = json.loads(approvals_path.read_text())
    assert set(data.keys()) == {t1, t2}
    assert data[t1]["entries"]["1"]["from_domain"] == "a.test"
    assert data[t2]["entries"]["1"]["from_domain"] == "b.test"


def test_report_30_day_expiry_prunes_old_tokens(approvals_path):
    old = {"oldtok": {"created": (datetime.now()
                                  - timedelta(days=31)).isoformat(),
                      "account": "Acct", "window_end": "x",
                      "entries": {"1": {"from_domain": "old.test",
                                        "from": "", "subject": ""}}},
           "recenttok": {"created": (datetime.now()
                                     - timedelta(days=5)).isoformat(),
                         "account": "Acct", "window_end": "x",
                         "entries": {}}}
    approvals_path.write_text(json.dumps(old))
    daily_report.record_report_approvals(
        "newtok", "Acct", datetime.now(),
        {"1": {"from_domain": "new.test", "from": "", "subject": ""}},
        _LOGGER)
    data = json.loads(approvals_path.read_text())
    assert "oldtok" not in data                 # pruned (>30 days)
    assert "recenttok" in data                  # kept (<30 days)
    assert "newtok" in data


def test_spam_filter_reader_sees_daily_report_writes(approvals_path,
                                                     monkeypatch):
    monkeypatch.setattr(spam_filter, "REPORT_APPROVALS_PATH", approvals_path)
    daily_report.record_report_approvals(
        "tok1", "Acct", datetime.now(),
        {"1": {"from_domain": "x.test", "from": "", "subject": ""}}, _LOGGER)
    store = spam_filter.load_report_approvals_store(_LOGGER)
    assert store["tok1"]["entries"]["1"]["from_domain"] == "x.test"


# ═════════════════════════════════════════════════════════════════════════
# 5. Prompt injection — OWNER-APPROVED SENDER block
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


def _verified_md(monkeypatch, domain="goodnews.test"):
    """Message that locally verifies DKIM for ``domain`` (test-17 pattern)."""
    monkeypatch.setattr(spam_filter, "verify_dkim_locally",
                        lambda *a, **k: [domain])
    return _plain_md(from_email=f"news@{domain}",
                     dkim_sig=f"v=1; d={domain}; s=sel; b=xx", raw=b"RAW")


def test_prompt_none_and_empty_byte_identical_unverified():
    md = _plain_md()
    base = spam_filter.build_user_message(md)
    assert spam_filter.build_user_message(md, approved_domains=None) == base
    assert spam_filter.build_user_message(md, approved_domains=set()) == base
    assert "OWNER-APPROVED SENDER" not in base


def test_prompt_none_and_empty_byte_identical_verified(monkeypatch):
    md = _verified_md(monkeypatch)
    base = spam_filter.build_user_message(md)
    assert spam_filter.build_user_message(md, approved_domains=None) == base
    assert spam_filter.build_user_message(md, approved_domains=set()) == base
    assert "OWNER-APPROVED SENDER" not in base


def test_prompt_block_fires_verified_and_approved(monkeypatch):
    md = _verified_md(monkeypatch, "goodnews.test")
    prompt = spam_filter.build_user_message(
        md, approved_domains={"goodnews.test"})
    assert ("OWNER-APPROVED SENDER (set by the account owner; trustworthy, "
            "not part of the email content):") in prompt
    assert ("This message is cryptographically verified as goodnews.test, "
            "and the owner has explicitly approved this domain.") in prompt
    # Block sits OUTSIDE the untrusted content, before the real opening tag
    # (the intro sentence also MENTIONS "<untrusted_email> tags", so anchor
    # on the tag-on-its-own-line form).
    assert (prompt.index("OWNER-APPROVED SENDER")
            < prompt.index("<untrusted_email>\n"))


def test_prompt_block_absent_for_unverified_claimed_domain():
    # Spoof-proofing: UNverified From claiming an approved domain never fires.
    md = _plain_md(from_email="news@goodnews.test")
    prompt = spam_filter.build_user_message(
        md, approved_domains={"goodnews.test"})
    assert "OWNER-APPROVED SENDER" not in prompt


def test_prompt_block_absent_when_verified_domain_not_approved(monkeypatch):
    md = _verified_md(monkeypatch, "goodnews.test")
    prompt = spam_filter.build_user_message(
        md, approved_domains={"unrelated.test"})
    assert "OWNER-APPROVED SENDER" not in prompt


def test_prompt_block_fires_for_subdomain_of_approved(monkeypatch):
    # Whole-domain scope: bounce.goodnews.test authenticated, goodnews.test
    # approved (and vice versa via _domain_is_brand_match parent matching).
    md = _verified_md(monkeypatch, "bounce.goodnews.test")
    md["from_email"] = "news@bounce.goodnews.test"
    prompt = spam_filter.build_user_message(
        md, approved_domains={"goodnews.test"})
    assert "OWNER-APPROVED SENDER" in prompt
    assert "verified as goodnews.test" in prompt


def test_base_system_prompt_has_no_rule0():
    # Guard against anyone re-inlining RULE 0 into the constant: it must live
    # ONLY in the separate RULE_0_TEXT fragment. Byte-identity of the shipped
    # (no-approvals) prompt vs git HEAD is established structurally by the diff.
    assert "RULE 0" not in spam_filter.BASE_SYSTEM_PROMPT
    assert "SUBORDINATE to RULE 0" not in spam_filter.BASE_SYSTEM_PROMPT


def test_build_classifier_prompt_default_omits_rule0():
    # Default (approvals_active=False, the shipped-default case): NEITHER new
    # fragment appears.
    p = spam_filter.build_classifier_prompt({"signals": {}})
    assert "RULE 0" not in p
    assert spam_filter.RULE_0_TEXT not in p
    assert spam_filter.RULE_0_SUBORDINATION_LINE not in p


def test_build_classifier_prompt_active_splices_rule0():
    p = spam_filter.build_classifier_prompt({"signals": {}},
                                            approvals_active=True)
    assert spam_filter.RULE_0_TEXT in p
    assert spam_filter.RULE_0_SUBORDINATION_LINE in p
    # RULE 0 sits immediately above RULE 1.
    assert p.index("RULE 0 —") < p.index("RULE 1 —")
    # Subordination line sits under the hard-signals header, above signal #1.
    assert (p.index(spam_filter.RULE_0_SUBORDINATION_LINE)
            < p.index("1. DOMAIN_BRAND_MISMATCH"))


def test_build_classifier_prompt_default_byte_identical_to_no_flag():
    # The default call and an explicit approvals_active=False call are identical.
    sig = {"signals": {}}
    assert (spam_filter.build_classifier_prompt(sig)
            == spam_filter.build_classifier_prompt(sig, approvals_active=False))


# ═════════════════════════════════════════════════════════════════════════
# 6. Behavioral wiring
# ═════════════════════════════════════════════════════════════════════════

def test_pre_classifier_hard_gate_runs_before_classify(monkeypatch):
    # The pre-classifier hard-signal short-circuit sits BEFORE the AI call in
    # run_filter, so an approved domain can never override a hard signal
    # (assert via source ordering, as test_session8.py:174 does).
    src = inspect.getsource(spam_filter.run_filter)
    pre_pos = src.index('pre_result["pre_classifier_verdict"] == "SPAM"')
    ai_pos = src.index("approved_domains=approved_domains")
    assert pre_pos < ai_pos, (
        "pre-classifier hard gate must run before the approved-aware AI call")


def test_hard_signal_still_junks_approved_verified_sender(monkeypatch):
    # Behavioral: a pre-classifier hard verdict junks the mail without any AI
    # call, even though the sender's domain is owner-approved and the message
    # would have carried the OWNER-APPROVED block.
    md = _plain_md(from_email="news@goodnews.test")
    md.update({"message_id": "<hard-1@x>", "from_header_raw":
               "Good News <news@goodnews.test>"})

    def _pre(headers, body, sending_ip=None, dnsbl_timeout=None):
        return {"pre_classifier_verdict": "SPAM",
                "pre_classifier_confidence": 0.99,
                "hard_signals": ["DOMAIN_BRAND_MISMATCH"],
                "soft_signals": [], "signal_details": {}}

    monkeypatch.setattr(spam_filter, "check_header_signals", _pre)
    calls_out = _approve_harness(monkeypatch, msg_data=md,
                                 approvals_store={})
    assert calls_out["execute_spam_action"] == 1   # junked by hard gate
    assert calls_out["classify_email"] == 0        # AI never consulted


@pytest.mark.parametrize("auth_dom,approved,expect", [
    ("goodnews.test", "goodnews.test", True),       # exact
    ("bounce.goodnews.test", "goodnews.test", True),  # sub of approved
    ("goodnews.test", "mail.goodnews.test", True),    # parent of approved
    ("evil.test", "goodnews.test", False),            # unrelated
    ("notgoodnews.test", "goodnews.test", False),     # suffix trickery
])
def test_domain_is_brand_match_whole_domain_scope(auth_dom, approved, expect):
    assert spam_filter._domain_is_brand_match(auth_dom, approved) is expect


# ═════════════════════════════════════════════════════════════════════════
# 7. Whitelist isolation
# ═════════════════════════════════════════════════════════════════════════

def test_approval_functions_never_touch_whitelist():
    for fn in (spam_filter.load_approved_senders,
               spam_filter.save_approved_senders,
               spam_filter.add_approved_domain,
               spam_filter.load_report_approvals_store,
               spam_filter.parse_approve_command,
               daily_report.load_report_approvals,
               daily_report.save_report_approvals,
               daily_report.build_approval_entries,
               daily_report.record_report_approvals):
        src = inspect.getsource(fn)
        assert "check_whitelist" not in src, fn.__name__
        assert "check_whitelist_address_only" not in src, fn.__name__
        assert "whitelist.json" not in src, fn.__name__
        assert "WHITELIST_PATH" not in src, fn.__name__


def test_precedence_whitelist_blocks_unchanged():
    src = inspect.getsource(spam_filter.run_filter)
    # Precedence-1 (address whitelist) and precedence-4 (domain whitelist)
    # still present, verbatim call shapes.
    assert ("wl_addr_match = check_whitelist_address_only(from_header_raw, "
            "whitelist)") in src
    assert "wl_match = check_whitelist(from_header_raw, whitelist)" in src
    assert "# --- Precedence check 1: Whitelist specific address ---" in src
    assert "# --- Precedence check 4: Whitelist domain ---" in src
    # Finding #6: the APPROVE branch may WRITE the whitelist's domain tier
    # (add_whitelist_domain, Case B) but must never READ whitelist state —
    # the precedence checks above remain the only readers in run_filter.
    branch = src[src.index("Detection branch 2b"):
                 src.index("# --- Precedence check 1")]
    assert "check_whitelist" not in branch
    assert "load_whitelist" not in branch
    assert "WHITELIST_PATH" not in branch


def test_approved_store_separate_file():
    assert spam_filter.APPROVED_SENDERS_PATH.name == "approved_senders.json"
    assert spam_filter.APPROVED_SENDERS_PATH != spam_filter.WHITELIST_PATH


# ═════════════════════════════════════════════════════════════════════════
# 8. Install seeding — defaults shipped + both runtime seed lists
# ═════════════════════════════════════════════════════════════════════════

def test_default_file_shipped():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    p = os.path.join(root, "resources", "defaults", "approved_senders.json")
    with open(p) as f:
        data = json.load(f)
    assert data == {"domains": []}


def test_bootstrap_seeds_approved_senders():
    from mailwarden_app import bootstrap
    src = inspect.getsource(bootstrap)
    assert '"approved_senders.json"' in src


def test_setup_assistant_seeds_approved_senders():
    from mailwarden_app import setup_assistant
    src = inspect.getsource(setup_assistant.SetupAssistant._install_defaults)
    assert '"approved_senders.json"' in src


# ═════════════════════════════════════════════════════════════════════════
# 9. Finding #6 — block-source classification, report partition, and
#    per-source honest APPROVE
# ═════════════════════════════════════════════════════════════════════════

def _log_rec(ts, decision, action, acct="Acct",
             from_line="Bad <b@bad.test>", subject="pitch", signals="x"):
    """One decisions.log record in log_decision's exact line format
    (without the trailing '  ---\\n' separator).

    Finding #12 fixture note: the MESSAGE-ID is derived from (from_line,
    subject) instead of a shared constant — parse_decisions_24h now
    deduplicates exact (message-id, kind) repeats, so DISTINCT fixture
    messages must carry distinct ids, exactly as real log_decision records
    would."""
    return (f"[{ts}] ACCOUNT: {acct}\n"
            f"  MESSAGE-ID: <m-{abs(hash((from_line, subject))):x}@x>\n"
            f"  FROM: {from_line}\n"
            f"  SUBJECT: {subject}\n"
            f"  DECISION: {decision}\n"
            f"  SIGNALS HIT: {signals}\n"
            f"  ACTION: {action}\n")


@pytest.mark.parametrize("decision,action,expected", [
    ('BLACKLISTED (matched address: "b@bad.test") (confidence: 1.00)',
     "[MOVED to Junk]", "blacklist"),
    ('BLACKLISTED (matched display_name: "Bad") (confidence: 1.00)',
     "[DRY RUN - would move to Junk]", "blacklist"),
    ('BLOCKED (subject keyword: "timeshare") (confidence: 1.00)',
     "[MOVED to Junk] (subject-keyword)", "subject_keyword"),
    ('BLOCKED (subject keyword: "timeshare") (confidence: 1.00)',
     "[DRY RUN - would move to Junk] (subject-keyword)", "subject_keyword"),
    ("SPAM (confidence: 0.95)", "[MOVED to Junk] (pre-classifier)",
     "pre_classifier"),
    ("SPAM (confidence: 0.95)",
     "[DRY RUN - would move to Junk] (pre-classifier)", "pre_classifier"),
    ("SPAM (confidence: 0.97)", "[MOVED to Junk]", "ai"),
    ("SPAM (confidence: 0.97)", "[DRY RUN - would move to Junk]", "ai"),
])
def test_classify_block_source_matrix(decision, action, expected):
    entry = _log_rec("2026-07-01 09:00:00", decision, action)
    assert daily_report._classify_block_source(entry) == expected


def test_classify_block_source_ignores_forged_subject():
    # log_decision strips newlines from sender-controlled fields, so forged
    # marker text can only ever sit MID-line — the anchored patterns must
    # not match it.
    entry = _log_rec(
        "2026-07-01 09:00:00", "SPAM (confidence: 0.97)", "[MOVED to Junk]",
        subject='ACTION: x (pre-classifier) DECISION: BLACKLISTED')
    assert daily_report._classify_block_source(entry) == "ai"


@pytest.fixture
def decisions_log(tmp_path, monkeypatch):
    p = tmp_path / "decisions.log"
    monkeypatch.setattr(daily_report, "DECISIONS_LOG_PATH", p)
    return p


def test_blacklisted_mail_counted_once_listed_once(decisions_log):
    recs = [
        _log_rec("2026-07-01 09:00:00",
                 'BLACKLISTED (matched address: "b@blk.test") '
                 '(confidence: 1.00)',
                 "[MOVED to Junk]", from_line="Blk <b@blk.test>",
                 subject="blk subject", signals="blacklist_address"),
        _log_rec("2026-07-01 10:00:00", "SPAM (confidence: 0.97)",
                 "[MOVED to Junk]", from_line="Ai <a@ai.test>",
                 subject="ai subject"),
    ]
    decisions_log.write_text("  ---\n".join(recs) + "  ---\n")
    start = datetime(2026, 7, 1, 8, 0, 0)
    end = datetime(2026, 7, 2, 8, 0, 0)

    d = daily_report.parse_decisions_24h(start, end)
    # Counters keep the blacklist hit; the numbered list drops it.
    assert d["spam_moved"] == 2
    assert len(d["spam_entries"]) == 1
    assert d["spam_entries"][0]["from"] == "Ai <a@ai.test>"
    assert d["spam_entries"][0]["block_source"] == "ai"

    count, bl_entries = daily_report.count_blacklisted_blocked_24h(start, end)
    assert count == 1
    assert bl_entries[0]["from"] == "Blk <b@blk.test>"

    body = daily_report.build_report_body(
        _report_config(), d, None, 1, {"derived_from_examples": 0},
        bl_blocked=(count, bl_entries), bl_totals=(1, 0))
    # The blacklisted sender renders exactly ONCE — in BLACKLIST ACTIVITY,
    # not in the numbered junk list.
    assert body.count("Blk <b@blk.test>") == 1
    assert "BLACKLIST ACTIVITY" in body
    assert "1. 10:00 AM | Ai <a@ai.test>" in body
    assert "2. " not in body.split("BLACKLIST ACTIVITY")[0]
    # The per-type undo hint renders with the blocked list.
    assert ("To unblock one of these senders: for an address or name, "
            "forward a message from that sender with the subject "
            "\"Fwd: Remove from Blacklist\". For a domain or subject "
            "keyword, open the Dashboard's Blacklist tab, select the "
            "entry, and click Remove.") in body


def test_unblock_hint_absent_without_blacklist_activity():
    body = daily_report.build_report_body(
        _report_config(), _decisions(moved=1, dry=0), None, 0,
        {"derived_from_examples": 0})
    assert "To unblock one of these senders" not in body


def test_token_map_excludes_blacklist_and_carries_block_source(decisions_log):
    recs = [
        _log_rec("2026-07-01 09:00:00",
                 'BLACKLISTED (matched address: "b@blk.test") '
                 '(confidence: 1.00)',
                 "[MOVED to Junk]", from_line="Blk <b@blk.test>",
                 signals="blacklist_address"),
        _log_rec("2026-07-01 09:10:00",
                 'BLOCKED (subject keyword: "timeshare") (confidence: 1.00)',
                 "[MOVED to Junk] (subject-keyword)",
                 from_line="Kw <k@kw.test>", subject="timeshare deal",
                 signals="subject_keyword"),
        _log_rec("2026-07-01 09:20:00", "SPAM (confidence: 0.95)",
                 "[MOVED to Junk] (pre-classifier)",
                 from_line="Pre <p@dnsbl.test>", signals="dnsbl_listed"),
        _log_rec("2026-07-01 09:30:00", "SPAM (confidence: 0.97)",
                 "[MOVED to Junk]", from_line="Ai <a@ai.test>"),
    ]
    decisions_log.write_text("  ---\n".join(recs) + "  ---\n")
    d = daily_report.parse_decisions_24h(datetime(2026, 7, 1, 8, 0, 0),
                                         datetime(2026, 7, 2, 8, 0, 0))
    entries = daily_report.build_approval_entries(d)
    # Blacklist entry excluded; numbering is 1..3 over the survivors in
    # rendered order.
    assert set(entries.keys()) == {"1", "2", "3"}
    assert entries["1"]["from_domain"] == "kw.test"
    assert entries["1"]["block_source"] == "subject_keyword"
    assert entries["2"]["from_domain"] == "dnsbl.test"
    assert entries["2"]["block_source"] == "pre_classifier"
    assert entries["3"]["from_domain"] == "ai.test"
    assert entries["3"]["block_source"] == "ai"


def test_token_map_block_source_defaults_ai_for_legacy_entries():
    # _decisions() spam entries predate block_source — the token map must
    # degrade them to the AI path, not crash.
    entries = daily_report.build_approval_entries(_decisions(moved=1, dry=0))
    assert entries["1"]["block_source"] == "ai"


# --- APPROVE handler: per-source branches (run_filter harness) -----------

def _token_store_with_sources():
    return _fresh_token_store(entries={
        "1": {"from_domain": "kw.test", "from": "Kw <k@kw.test>",
              "subject": "timeshare deal", "block_source": "subject_keyword"},
        "2": {"from_domain": "dnsbl.test", "from": "Pre <p@dnsbl.test>",
              "subject": "hello", "block_source": "pre_classifier"},
        "3": {"from_domain": "ai.test", "from": "Ai <a@ai.test>",
              "subject": "buy", "block_source": "ai"},
    })


def test_branch_keyword_item_honest_noop(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 1"),
                             approvals_store=_token_store_with_sources())
    assert calls["add_approved_domain"] == []
    assert calls["add_whitelist_domain"] == []
    assert calls["mark_uid_seen"] == 1
    assert calls["classify_email"] == 0
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("Item 1 was blocked by a subject-keyword rule you set "
                    "up, so approving the sender won't stop it. To remove "
                    "the keyword, open the Dashboard, go to the Blacklist "
                    "tab, select the keyword, and click Remove. No change "
                    "was made.")


def test_branch_pre_classifier_item_whitelists_domain(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 2"),
                             approvals_store=_token_store_with_sources())
    assert calls["add_whitelist_domain"] == ["dnsbl.test"]
    assert calls["add_approved_domain"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("Added dnsbl.test to your trusted senders — future mail "
                    "from this domain won't be blocked by MailWarden's "
                    "built-in spam checks.")


def test_branch_pre_classifier_item_already_trusted(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 2"),
                             approvals_store=_token_store_with_sources(),
                             add_wl_returns=False)
    assert calls["add_whitelist_domain"] == ["dnsbl.test"]
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("dnsbl.test is already on your trusted senders — "
                    "no change.")


def test_branch_ai_item_unchanged_by_sources(monkeypatch):
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 3"),
                             approvals_store=_token_store_with_sources())
    assert calls["add_approved_domain"] == ["ai.test"]
    assert calls["add_whitelist_domain"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body == ("Approved: ai.test (item 3). This applies whenever a "
                    "message is verified as genuinely from that domain. "
                    "Mail that can't be verified will still be judged "
                    "normally.")


def test_branch_legacy_token_without_block_source_uses_ai_path(monkeypatch):
    # _fresh_token_store's default entries predate block_source — behavior
    # must stay byte-identical to the pre-#6 AI path.
    calls = _approve_harness(monkeypatch, msg_data=_mwr_msg(body="APPROVE 1"),
                             approvals_store=_fresh_token_store())
    assert calls["add_approved_domain"] == ["newsletter.test"]
    assert calls["add_whitelist_domain"] == []
    subject, body, to_addr = calls["send_email"][0]
    assert body.startswith("Approved: newsletter.test (item 1).")


def test_branch_mixed_sources_each_number_honest(monkeypatch):
    calls = _approve_harness(monkeypatch,
                             msg_data=_mwr_msg(body="APPROVE 1 2 3"),
                             approvals_store=_token_store_with_sources())
    assert calls["add_whitelist_domain"] == ["dnsbl.test"]
    assert calls["add_approved_domain"] == ["ai.test"]
    subject, body, to_addr = calls["send_email"][0]
    assert "Item 1 was blocked by a subject-keyword rule" in body
    assert "Added dnsbl.test to your trusted senders" in body
    assert "Approved: ai.test (item 3)." in body
    # One ack line per number, in one email.
    assert len(calls["send_email"]) == 1


# --- Case B mechanics with REAL files -------------------------------------

def test_add_whitelist_domain_real_store(tmp_path, monkeypatch):
    wl_path = tmp_path / "whitelist.json"
    monkeypatch.setattr(spam_filter, "WHITELIST_PATH", wl_path)
    assert spam_filter.add_whitelist_domain("@Blocked.Example.COM",
                                            _LOGGER) is True
    assert spam_filter.add_whitelist_domain("blocked.example.com",
                                            _LOGGER) is False
    assert spam_filter.add_whitelist_domain("", _LOGGER) is False
    assert spam_filter.add_whitelist_domain(None, _LOGGER) is False
    on_disk = json.loads(wl_path.read_text())
    assert on_disk["domains"] == ["blocked.example.com"]
    assert "last_updated" in on_disk
    assert not any(k.startswith("_") for k in on_disk)
    leftovers = [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
    assert leftovers == []


def test_add_whitelist_domain_preserves_existing_entries(tmp_path,
                                                         monkeypatch):
    wl_path = tmp_path / "whitelist.json"
    wl_path.write_text(json.dumps({"version": "1.0",
                                   "addresses": ["keep@x.test"],
                                   "domains": ["old.test"]}))
    monkeypatch.setattr(spam_filter, "WHITELIST_PATH", wl_path)
    assert spam_filter.add_whitelist_domain("new.test", _LOGGER) is True
    on_disk = json.loads(wl_path.read_text())
    assert on_disk["addresses"] == ["keep@x.test"]
    assert on_disk["domains"] == ["old.test", "new.test"]


def test_case_b_domain_passes_whitelist_check_incl_subdomain(tmp_path,
                                                             monkeypatch):
    wl_path = tmp_path / "whitelist.json"
    monkeypatch.setattr(spam_filter, "WHITELIST_PATH", wl_path)
    spam_filter.add_whitelist_domain("dnsbl.test", _LOGGER)
    wl = spam_filter.load_whitelist(_LOGGER)
    # The rescued domain (and its subdomains, F4) now passes the domain
    # whitelist that runs BEFORE the pre-classifier.
    assert spam_filter.check_whitelist("Pre <p@dnsbl.test>", wl)
    assert spam_filter.check_whitelist("Pre <p@mail.dnsbl.test>", wl)
    assert not spam_filter.check_whitelist("Evil <e@notdnsbl.test>", wl)


def test_case_b_whitelist_domain_cannot_override_blacklist(tmp_path,
                                                           monkeypatch):
    # The whitelist-domain tier runs AFTER the blacklist in run_filter, so
    # a Case B rescue can never override an owner-set block: check_blacklist
    # still matches the sender.
    wl_path = tmp_path / "whitelist.json"
    bl_path = tmp_path / "blacklist.json"
    monkeypatch.setattr(spam_filter, "WHITELIST_PATH", wl_path)
    monkeypatch.setattr(spam_filter, "BLACKLIST_PATH", bl_path)
    bl_path.write_text(json.dumps({"version": "1.0",
                                   "addresses": ["p@dnsbl.test"],
                                   "display_names": [], "domains": [],
                                   "subject_keywords": []}))
    spam_filter.add_whitelist_domain("dnsbl.test", _LOGGER)
    bl = spam_filter.load_blacklist(_LOGGER)
    mt, mv = spam_filter.check_blacklist("Pre <p@dnsbl.test>", bl,
                                         account_name="owner@example.com")
    assert mt  # blacklist still fires despite the whitelisted domain


def test_case_b_rescued_domain_bypasses_pre_classifier(monkeypatch):
    # A message whose ONLY problem is a pre-classifier SPAM verdict: junked
    # without the rescue, passed through once the domain is whitelisted.
    monkeypatch.setattr(spam_filter, "record_pre_classifier_skip",
                        lambda *a, **k: None)

    def _pre(*a, **k):
        return {"pre_classifier_verdict": "SPAM",
                "pre_classifier_confidence": 0.99,
                "hard_signals": ["dnsbl_listed"], "soft_signals": []}
    monkeypatch.setattr(spam_filter, "check_header_signals", _pre)

    md = _mwr_msg(subject="hello there", body="ordinary text",
                  from_email="p@dnsbl.test")

    # Control: no whitelist -> pre-classifier junks it.
    calls = _approve_harness(monkeypatch, msg_data=md, approvals_store={})
    assert calls["execute_spam_action"] == 1

    # Rescued: domain on the whitelist tier -> passed through, no spam
    # action, no classification.
    wl = {"domains": ["dnsbl.test"], "addresses": [],
          "_addresses_set": set(), "_domains_set": {"dnsbl.test"}}
    calls = _approve_harness(monkeypatch, msg_data=md, approvals_store={},
                             whitelist=wl)
    assert calls["execute_spam_action"] == 0
    assert calls["classify_email"] == 0

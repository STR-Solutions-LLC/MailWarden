#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Wave-4 — reply-corridor redesign (drop the \\Seen dependency) + always-screen
approved senders (remove the gate-6 no-curate AI-skip).

CHANGE 1 (reply corridor): command replies are found by a per-(account, folder,
UIDVALIDITY) UID-range watermark (or a bounded SINCE lookback on first run /
UIDVALIDITY reset), NOT by an UNSEEN search — so a YES/APPROVE/numbered reply is
honored whether or not the owner's mail client has already marked it read. The
command scan is exempt from the per-run caps, and each command's Message-ID is
persisted+flushed BEFORE the handler runs (at-most-once).

CHANGE 2 (always-screen): approved + authenticated mail is no longer delivered
without AI review — the old cost-skip gate was removed, so every approved +
authenticated message routes to the classifier (with the OWNER-APPROVED prompt
block + RULE 0 protections).

Harness mirrors tests/test_finalize_seen_timing.py._run_harness (a full
spam_filter.run_filter(force=True) drive with every IO/network call mocked),
extended with mockable command-scan state + a fetch_command_scan_uids override.
"""
import email as _email
import logging as _logging
import os
import sys
from datetime import datetime, timedelta

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_wave4")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


# ═════════════════════════════════════════════════════════════════════════
# Part A — fetch_command_scan_uids unit behavior (fake IMAP conn)
# ═════════════════════════════════════════════════════════════════════════

class _FakeSearchConn:
    """Minimal IMAP conn supporting select/status/uid-SEARCH for the command
    scan. `search_result` is the list of UID bytes the SEARCH returns."""
    def __init__(self, uidvalidity, uidnext, search_result,
                 select_status="OK"):
        self.uidvalidity = uidvalidity
        self.uidnext = uidnext
        self.search_result = search_result
        self.select_status = select_status
        self.search_args = None

    def select(self, folder):
        return (self.select_status, [b"1"])

    def status(self, folder, what):
        if "UIDVALIDITY" in what:
            return ("OK", [f'"{folder}" (UIDVALIDITY {self.uidvalidity})'.encode()])
        if "UIDNEXT" in what:
            if self.uidnext is None:
                return ("NO", [None])
            return ("OK", [f'"{folder}" (UIDNEXT {self.uidnext})'.encode()])
        return ("NO", [None])

    def uid(self, cmd, *args):
        if cmd == "SEARCH":
            # RFC 3501/9051 §6.4.8: in a SEARCH command a bare number set means
            # message SEQUENCE numbers, even inside UID SEARCH — a UID range
            # needs the explicit "UID" search key. Reject the broken wire form
            # (the raise is swallowed by fetch_command_scan_uids's fail-safe
            # except, but that yields ([], None) + unset search_args, which
            # fails the caller's assertions) so this class of bug can never
            # silently pass again.
            import re as _re
            keys = [a for a in args if a is not None]
            for i, key in enumerate(keys):
                # A number set is digits/':'/','/'*' only (e.g. "21:*") —
                # dates like "30-Jun-2026" are not number sets.
                if isinstance(key, str) and _re.fullmatch(r"[\d:,*]+", key):
                    if i == 0 or keys[i - 1] != "UID":
                        raise AssertionError(
                            f"bare number set {key!r} in SEARCH is a SEQUENCE-"
                            f"number set, not UIDs — it must follow the 'UID' "
                            f"search key")
            self.search_args = args
            return ("OK", [b" ".join(self.search_result)])
        return ("NO", [None])


def test_first_run_uses_since_lookback_and_sets_watermark():
    conn = _FakeSearchConn(uidvalidity=100, uidnext=50,
                           search_result=[b"10", b"20", b"49"])
    uids, update = spam_filter.fetch_command_scan_uids(
        conn, "INBOX", _LOGGER, stored_entry=None)
    assert uids == [b"10", b"20", b"49"]
    assert update == {"uidvalidity": 100, "uid_watermark": 49}
    # First run must use a bounded SINCE lookback, NOT a full/range scan.
    assert conn.search_args[1] == "SINCE"


def test_incremental_uses_uid_range_and_filters_boundary():
    # watermark 20, UIDVALIDITY matches -> UID range "21:*"; a boundary
    # re-match at or below the watermark (15) must be filtered out.
    conn = _FakeSearchConn(uidvalidity=100, uidnext=50,
                           search_result=[b"15", b"21", b"30"])
    uids, update = spam_filter.fetch_command_scan_uids(
        conn, "INBOX", _LOGGER,
        stored_entry={"uidvalidity": 100, "uid_watermark": 20})
    assert uids == [b"21", b"30"]
    assert update == {"uidvalidity": 100, "uid_watermark": 49}
    # The explicit "UID" search key is REQUIRED on the wire: a bare "21:*"
    # would be a message-SEQUENCE-number set (RFC 3501/9051 §6.4.8) and, since
    # the watermark is UIDNEXT-derived while expunges shrink EXISTS, would
    # collapse to only the highest message and silently lose earlier replies.
    assert conn.search_args == (None, "UID", "21:*")


def test_uidvalidity_mismatch_resets_to_lookback():
    # Stored UIDVALIDITY 100 but the mailbox now reports 200 (rebuilt): fall
    # back to the SINCE lookback and store the NEW UIDVALIDITY.
    conn = _FakeSearchConn(uidvalidity=200, uidnext=60, search_result=[b"5"])
    uids, update = spam_filter.fetch_command_scan_uids(
        conn, "INBOX", _LOGGER,
        stored_entry={"uidvalidity": 100, "uid_watermark": 20})
    assert uids == [b"5"]
    assert update == {"uidvalidity": 200, "uid_watermark": 59}
    assert conn.search_args[1] == "SINCE"


def test_select_failure_scans_nothing_and_keeps_watermark():
    conn = _FakeSearchConn(uidvalidity=100, uidnext=50, search_result=[b"9"],
                           select_status="NO")
    uids, update = spam_filter.fetch_command_scan_uids(
        conn, "INBOX", _LOGGER, stored_entry=None)
    assert uids == []
    assert update is None  # caller leaves the stored watermark untouched


def test_state_file_roundtrip(tmp_path, monkeypatch):
    path = tmp_path / "command_scan_state.json"
    monkeypatch.setattr(spam_filter, "COMMAND_SCAN_STATE_PATH", path)
    # Missing file -> safe empty default.
    assert spam_filter.load_command_scan_state()["folders"] == {}
    state = {"version": "1.0", "last_updated": "", "folders": {
        _ACCOUNT_KEY: {"INBOX": {"uidvalidity": 100, "uid_watermark": 42}}}}
    spam_filter.save_command_scan_state(state)
    loaded = spam_filter.load_command_scan_state()
    assert loaded["folders"][_ACCOUNT_KEY]["INBOX"] == {
        "uidvalidity": 100, "uid_watermark": 42}


# ═════════════════════════════════════════════════════════════════════════
# Part B — run_filter integration harness
# ═════════════════════════════════════════════════════════════════════════

def _msg(msg_id, subject, body, from_email=_ACCOUNT_KEY):
    return {
        "message_id": msg_id, "from_email": from_email,
        "from_display_name": "Owner", "subject": subject,
        "plain_text_body": body, "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }


def _run_harness(monkeypatch, *, command_uid_to_msg=None, unseen_uid_to_msg=None,
                 cmd_state_update=None, approvals_store=None, pending=None,
                 approved_domains=None, verified_domain=None,
                 max_junk_actions=25, real_prompt=False, patches=None,
                 folders=("INBOX",), command_scan_by_folder=None):
    """Drive run_filter(force=True). `command_uid_to_msg` is the map returned by
    the (mocked) command scan; `unseen_uid_to_msg` the UNSEEN classify set
    (returned only for INBOX). `command_scan_by_folder`, when given, overrides
    the per-folder command-scan result: {folder: (uid_list, state_update)};
    otherwise every folder returns (command_uid_to_msg keys, cmd_state_update).
    Returns a dict of spies including an ordered `events` log; `saved_state`
    snapshots the INBOX watermark entry at each save, `saved_state_all` the
    whole per-folder dict."""
    command_uid_to_msg = command_uid_to_msg or {}
    unseen_uid_to_msg = unseen_uid_to_msg or {}
    all_msgs = {}
    all_msgs.update(unseen_uid_to_msg)
    all_msgs.update(command_uid_to_msg)

    spies = {"classified": [], "send_email": [], "mark_uid_seen": 0,
             "processed": None, "saved_state": [], "saved_state_all": [],
             "events": [], "classify_calls": []}

    cfg = {
        "filter": {"dry_run": False, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50,
                   "max_junk_actions_per_run": max_junk_actions,
                   "log_level": "ERROR"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": _ACCOUNT_KEY,
                 "from_address": _ACCOUNT_KEY},
        "summary": {"recipient_address": _ACCOUNT_KEY},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{"name": "Acct", "enabled": True,
                      "username": _ACCOUNT_KEY,
                      "imap_host": "imap.example.com", "junk_folder": "Junk",
                      "folders_to_scan": list(folders)}],
    }

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_command_scan_state",
                        lambda: {"version": "1.0", "last_updated": "",
                                 "folders": {}})

    def _save_state(state):
        # Deep-ish snapshot of the INBOX entry at save time.
        entry = state.get("folders", {}).get(_ACCOUNT_KEY, {}).get("INBOX")
        spies["saved_state"].append(dict(entry) if entry else None)
        spies["saved_state_all"].append(
            {f: dict(e) for f, e in
             state.get("folders", {}).get(_ACCOUNT_KEY, {}).items()})
    monkeypatch.setattr(spam_filter, "save_command_scan_state", _save_state)

    monkeypatch.setattr(spam_filter, "load_dry_run_verdicts", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "persist_dry_run_verdicts", lambda dv: None)
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: {"domains": [], "addresses": [],
                                        "_addresses_set": set(),
                                        "_domains_set": set(),
                                        "_addresses_approve_set": set()})
    monkeypatch.setattr(spam_filter, "load_blacklist",
                        lambda logger: {"addresses": [], "domains": [],
                                        "display_names": [],
                                        "subject_keywords": []})
    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": list(approved_domains or []),
                                        "_domains_set": set(approved_domains or [])})
    monkeypatch.setattr(spam_filter, "detect_conflicts",
                        lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage", lambda: {})
    monkeypatch.setattr(spam_filter, "new_token_delta", lambda: {})
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: pending if pending is not None
                        else {"conversations": []})

    def _persist(processed, tu, td):
        spies["processed"] = processed
        spies["events"].append("persist_progress")
    monkeypatch.setattr(spam_filter, "persist_progress", _persist)

    if not real_prompt:
        monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                            lambda signals, username=None,
                            approvals_active=False,
                            whitelist_curate_active=False: "PROMPT")
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
    # Realistic owner check: True ONLY for the owner's own address (matches
    # production). The old unconditional `True` also made non-owner senders look
    # like the owner, which the owner-mail junking exemption (gate 0) would then
    # exempt — so approved/stranger mail must still reach the AI.
    monkeypatch.setattr(
        spam_filter, "_command_sender_is_owner",
        lambda from_email, *a, **k: (from_email or "").strip().lower()
        == _ACCOUNT_KEY)
    monkeypatch.setattr(spam_filter, "_command_auth_ok", lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "_notify_unverified_command",
                        lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: dict(approvals_store or {}))
    monkeypatch.setattr(spam_filter, "load_rule_reviews_store",
                        lambda logger: {})
    monkeypatch.setattr(spam_filter, "append_refinement_log",
                        lambda event: None)
    monkeypatch.setattr(spam_filter, "persist_pending_merge",
                        lambda pending, touched_ids=(), **k: None)
    monkeypatch.setattr(spam_filter, "add_blocklist_entry_local",
                        lambda value, kind, scope, logger: True)
    monkeypatch.setattr(spam_filter, "add_approved_domain",
                        lambda domain, logger: True)
    monkeypatch.setattr(spam_filter, "retire_ai_refinement",
                        lambda rid, logger: True)
    monkeypatch.setattr(spam_filter, "dequeue_rule_review",
                        lambda rid, logger: True)
    monkeypatch.setattr(spam_filter, "enqueue_rule_reviews",
                        lambda pairs, signals, logger: [])
    # Pre-classifier: benign (never junk) so approved mail reaches the AI.
    monkeypatch.setattr(spam_filter, "check_header_signals",
                        lambda *a, **k: None)
    if verified_domain is not None:
        monkeypatch.setattr(spam_filter, "verify_dkim_locally",
                            lambda *a, **k: [verified_domain])

    def _send(config, subject, body, logger, to_addr=None):
        spies["send_email"].append((subject, body, to_addr))
        spies["events"].append("send_email")
    monkeypatch.setattr(spam_filter, "send_email", _send)

    def _seen(conn, uid, logger):
        spies["mark_uid_seen"] += 1
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    def _classify(client, system_prompt, msg_data, *a, **k):
        spies["classified"].append(msg_data.get("message_id"))
        spies["classify_calls"].append(
            {"system_prompt": system_prompt,
             "approved_domains": k.get("approved_domains"),
             "msg_id": msg_data.get("message_id")})
        return ({"decision": "NOT_SPAM", "confidence": 0.0,
                 "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify)
    monkeypatch.setattr(spam_filter, "execute_spam_action",
                        lambda *a, **k: "moved")

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(
        spam_filter, "fetch_unseen_uids",
        lambda conn, folder, logger: (
            list(unseen_uid_to_msg) if folder == "INBOX" else []))

    def _cmd_scan(conn, folder, logger, stored_entry):
        if command_scan_by_folder is not None:
            uids, update = command_scan_by_folder.get(folder, ([], None))
            return list(uids), update
        return list(command_uid_to_msg), cmd_state_update
    monkeypatch.setattr(spam_filter, "fetch_command_scan_uids", _cmd_scan)

    def _fetch_mid(conn, uid, logger):
        return all_msgs[uid].get("message_id", "")
    monkeypatch.setattr(spam_filter, "fetch_message_id", _fetch_mid)
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"RAW:" + uid)

    def _extract(raw, own_hosts=None):
        uid = raw.split(b":", 1)[1]
        return dict(all_msgs[uid])
    monkeypatch.setattr(spam_filter, "extract_email_data", _extract)

    for name, fn in (patches or {}).items():
        monkeypatch.setattr(spam_filter, name, fn)

    spam_filter.run_filter(force=True)
    return spies


def _recorded(spies):
    ids = (spies["processed"] or {}).get("ids", {}).get(_ACCOUNT_KEY, [])
    return [e[0] for e in ids]


# ═════════════════════════════════════════════════════════════════════════
# Part C — reply corridor via run_filter
# ═════════════════════════════════════════════════════════════════════════

def test_read_reply_is_processed_even_though_not_unseen(monkeypatch):
    """The core Wave-4 fix: an APPROVE reply the owner's mail client has ALREADY
    marked read (so it is NOT in the UNSEEN set) is still picked up by the
    command scan and executed."""
    mid = "<approve-read@example.com>"
    approve = _msg(mid, "Re: MailWarden Report [MWR-tok1]", "APPROVE 1")
    store = {"tok1": {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": {"1": {"from_domain": "give.example",
                          "from": "News <n@give.example>", "subject": "s"}},
        "rule_reviews": {}}}
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={b"7": approve},   # command scan (read/unread agnostic)
        unseen_uid_to_msg={},                 # NOT in the UNSEEN set
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 7},
        approvals_store=store)
    assert mid in _recorded(spies), "read APPROVE reply must be handled"
    assert len(spies["send_email"]) == 1, "APPROVE must send its ack"
    assert mid not in spies["classified"], "a command must not be classified"


def test_command_scan_exempt_from_junk_cap(monkeypatch):
    """max_junk_actions_per_run=0 (cap hit immediately) must NOT starve the
    command scan — the owner's reply is still processed."""
    mid = "<approve-capped@example.com>"
    approve = _msg(mid, "Re: MailWarden Report [MWR-tok1]", "APPROVE 1")
    store = {"tok1": {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": {"1": {"from_domain": "give.example",
                          "from": "News <n@give.example>", "subject": "s"}},
        "rule_reviews": {}}}
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={b"9": approve},
        unseen_uid_to_msg={},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 9},
        approvals_store=store,
        max_junk_actions=0)
    assert mid in _recorded(spies), "command must run even when junk cap is 0"
    assert len(spies["send_email"]) == 1


def test_command_scan_does_not_classify_read_non_command(monkeypatch):
    """A read message pulled in by the command scan that is NOT a command must
    be left untouched — the corridor never classifies already-read mail."""
    mid = "<read-normal@example.com>"
    normal = _msg(mid, "Just a normal read email", "hello",
                  from_email="friend@somewhere.example")
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={b"3": normal},
        unseen_uid_to_msg={},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 3})
    assert mid not in spies["classified"], (
        "a read non-command message must NOT be classified by the command scan")
    assert mid not in _recorded(spies)


def test_unseen_non_command_still_classified(monkeypatch):
    """Regression guard: an UNSEEN non-command message is classified exactly as
    before (the corridor split must not drop normal classification)."""
    mid = "<unseen-normal@example.com>"
    normal = _msg(mid, "Fresh unread mail", "hello",
                  from_email="friend@somewhere.example")
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={},
        unseen_uid_to_msg={b"4": normal},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 4})
    assert mid in spies["classified"]


def test_watermark_persisted_after_folder_scan(monkeypatch):
    """The advanced watermark is persisted for the folder after its scan."""
    mid = "<x@example.com>"
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={},
        unseen_uid_to_msg={},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 88})
    assert {"uidvalidity": 100, "uid_watermark": 88} in spies["saved_state"]


def test_none_update_leaves_watermark_unpersisted(monkeypatch):
    """A ([], None) command-scan result (folder unscannable this tick) must NOT
    persist any watermark."""
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={},
        unseen_uid_to_msg={},
        cmd_state_update=None)
    assert spies["saved_state"] == [], "no watermark write when update is None"


def test_command_fetch_failure_suppresses_watermark_persist(monkeypatch):
    """Defect-2 guard: a command-scan UID whose full fetch fails (transient
    non-OK FETCH -> fetch_raw_email returns None) was never identified or
    precommitted — advancing the watermark past it would permanently lose the
    command. The folder's watermark persist must be suppressed for this tick so
    the next tick rescans the same range (Message-ID dedup makes that safe)."""
    mid = "<approve-lost@example.com>"
    approve = _msg(mid, "Re: MailWarden Report [MWR-tok1]", "APPROVE 1")
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={b"1": approve},
        unseen_uid_to_msg={},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 1},
        patches={"fetch_raw_email": lambda conn, uid, logger: None})
    assert spies["saved_state"] == [], (
        "a failed command-scan fetch must suppress the folder's watermark "
        "persist so the reply is rescanned next tick")
    assert mid not in _recorded(spies), (
        "the unfetched command must not be recorded (it was never identified)")
    assert spies["send_email"] == [], "no handler may run on a failed fetch"


def test_command_fetch_failure_leaves_other_folder_watermark_intact(monkeypatch):
    """Defect-2 isolation: the suppression is per folder. INBOX's command fetch
    fails (no INBOX watermark persist); the Archive folder's clean scan still
    persists its own watermark."""
    mid = "<approve-lost2@example.com>"
    approve = _msg(mid, "Re: MailWarden Report [MWR-tok1]", "APPROVE 1")
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={b"1": approve},
        unseen_uid_to_msg={},
        folders=("INBOX", "Archive"),
        command_scan_by_folder={
            "INBOX": ([b"1"], {"uidvalidity": 100, "uid_watermark": 10}),
            "Archive": ([], {"uidvalidity": 200, "uid_watermark": 5}),
        },
        patches={"fetch_raw_email": lambda conn, uid, logger: None})
    # Exactly one state save (Archive's); it must contain Archive and NOT INBOX.
    assert len(spies["saved_state_all"]) == 1
    saved = spies["saved_state_all"][0]
    assert saved.get("Archive") == {"uidvalidity": 200, "uid_watermark": 5}
    assert "INBOX" not in saved, (
        "INBOX's failed command fetch must not persist an INBOX watermark")


def test_persist_before_execute_ordering(monkeypatch):
    """At-most-once: the command's Message-ID is persisted (persist_progress)
    BEFORE the handler's side effect (send_email) runs."""
    mid = "<approve-order@example.com>"
    approve = _msg(mid, "Re: MailWarden Report [MWR-tok1]", "APPROVE 1")
    store = {"tok1": {
        "created": datetime.now().isoformat(), "account": "Acct",
        "window_end": datetime.now().isoformat(),
        "entries": {"1": {"from_domain": "give.example",
                          "from": "News <n@give.example>", "subject": "s"}},
        "rule_reviews": {}}}
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={b"5": approve},
        unseen_uid_to_msg={},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 5},
        approvals_store=store)
    ev = spies["events"]
    assert "persist_progress" in ev and "send_email" in ev
    assert ev.index("persist_progress") < ev.index("send_email"), (
        "Message-ID must be persisted BEFORE the handler side effect")


# ═════════════════════════════════════════════════════════════════════════
# Part D — always-screen approved senders (gate-6 removal)
# ═════════════════════════════════════════════════════════════════════════

def test_approved_authenticated_mail_now_reaches_the_ai(monkeypatch):
    """Approved + authenticated mail is NO LONGER delivered without AI review:
    it now reaches classify_email, carrying the approved_domains set (which
    drives the OWNER-APPROVED user block) and a RULE-0 system prompt."""
    mid = "<approved-msg@example.com>"
    approved = _msg(mid, "Your weekly digest", "hi there",
                    from_email="news@goodnews.test")
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={},
        unseen_uid_to_msg={b"2": approved},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 2},
        approved_domains={"goodnews.test"},
        verified_domain="goodnews.test",
        real_prompt=True)
    assert mid in spies["classified"], (
        "approved + authenticated mail must now be screened by the AI")
    call = spies["classify_calls"][0]
    assert "goodnews.test" in (call["approved_domains"] or set()), (
        "the OWNER-APPROVED path must be active (approved_domains forwarded)")
    assert "OWNER-APPROVED" in call["system_prompt"] or \
        "trustworthy" in call["system_prompt"], (
        "the RULE-0 owner-approved block must be spliced into the prompt")


def test_zero_approval_prompt_byte_identical_to_direct_build(monkeypatch):
    """Prompt-equivalence: for a message with NO approved senders, the system
    prompt run_filter feeds the classifier is byte-identical to building it
    directly, and no approved_domains are forwarded — the gate-6 removal did
    not change zero-approval prompt assembly."""
    mid = "<no-approval@example.com>"
    normal = _msg(mid, "Fresh unread mail", "hello",
                  from_email="stranger@somewhere.example")
    spies = _run_harness(
        monkeypatch,
        command_uid_to_msg={},
        unseen_uid_to_msg={b"6": normal},
        cmd_state_update={"uidvalidity": 100, "uid_watermark": 6},
        approved_domains=None,
        real_prompt=True)
    assert mid in spies["classified"]
    call = spies["classify_calls"][0]
    expected = spam_filter.build_classifier_prompt(
        {"signals": {}, "ai_refinements": []}, _ACCOUNT_KEY,
        approvals_active=False, whitelist_curate_active=False)
    assert call["system_prompt"] == expected, (
        "zero-approval system prompt must be byte-identical to HEAD's build")
    assert not (call["approved_domains"] or set()), (
        "no approved_domains may be forwarded when none are configured")
    assert "OWNER-APPROVED" not in call["system_prompt"]

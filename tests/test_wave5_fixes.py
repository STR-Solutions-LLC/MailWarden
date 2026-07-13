"""Wave-5 fix tests (E1-E9).

Covers the Fable integration-audit fixes implemented in this wave:
  E1  Dry Run must not advance/persist the command-scan watermark.
  E2  Train-folder learner reads HTML bodies (classifier parity).
  E3  FP self-mail no longer embeds the original spam subject in the Subject.
  E4  Auth-failed owner replies to a REAL pending conversation stay in the inbox.
  E5  Every registered self-mail type is body-marker protected.
  E6  Remove-from-Blacklist skips rule-owned entries (honest ack).
  E7  _teach_legit_blacklist_warning also detects active curate rules.
  E8  _expunge_one no longer self-reinforces its own deferrals.
  E9  precommit fires per genuine execution path, not on bare token match.
"""
import email as _email
import logging
import types

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "payload" / "MailWarden" / "src"))

import spam_filter  # noqa: E402

_LOG = logging.getLogger("wave5_test")
_LOG.addHandler(logging.NullHandler())


# --------------------------------------------------------------------------- #
# Shared run_filter harness (models test_fixes._dry_run_filter_harness but adds
# command-scan / approvals / expunge hooks the wave-5 tests need).
# --------------------------------------------------------------------------- #
def _harness(monkeypatch, *, msg_data=None, uids=None, dry_run=False,
             command_uids=None, cmd_state_update=None,
             approvals_store=None, pending=None, blacklist=None,
             signals=None, auth_ok=True, sender_is_owner=True,
             action_result="[MOVED to Junk]", classify_decision="SPAM"):
    calls = {
        "save_command_scan_state": 0,
        "send_email_args": [],
        "execute_spam_action": 0,
        "classify_email": 0,
        "mark_uid_seen": 0,
        "recorded_processed": [],   # msg_ids recorded to processed_ids
        "save_blacklist": 0,
    }
    cfg = {
        "filter": {"dry_run": dry_run, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        "anthropic": {"api_key": "", "model": "x", "max_tokens": 1,
                      "classify_mode": "single"},
        "smtp": {"host": "smtp.example.com", "username": "owner@example.com",
                 "from_address": "owner@example.com"},
        "summary": {"recipient": "owner@example.com"},
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
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOG)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: signals if signals is not None
                        else {"signals": {}})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: {"domains": [], "addresses": [],
                                        "_addresses_set": set(),
                                        "_domains_set": set()})
    _bl = blacklist if blacklist is not None else {
        "addresses": [], "domains": [], "display_names": [],
        "subject_keywords": []}
    monkeypatch.setattr(spam_filter, "load_blacklist", lambda logger: _bl)
    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": [], "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: dict(approvals_store or {}))
    monkeypatch.setattr(spam_filter, "detect_conflicts",
                        lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage", lambda: {})
    monkeypatch.setattr(spam_filter, "new_token_delta", lambda: {})
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: pending if pending is not None
                        else {"conversations": []})
    monkeypatch.setattr(spam_filter, "persist_progress",
                        lambda processed, tu, td: None)
    monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                        lambda signals, username=None, approvals_active=False,
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
    monkeypatch.setattr(spam_filter, "save_blacklist",
                        lambda data: calls.__setitem__(
                            "save_blacklist", calls["save_blacklist"] + 1))
    monkeypatch.setattr(spam_filter, "_command_sender_is_owner",
                        lambda *a, **k: sender_is_owner)
    monkeypatch.setattr(spam_filter, "_command_auth_ok", lambda *a, **k: auth_ok)
    monkeypatch.setattr(spam_filter, "_notify_unverified_command",
                        lambda *a, **k: None)

    def _send(config, subject, body, logger, **k):
        calls["send_email_args"].append((subject, body))
    monkeypatch.setattr(spam_filter, "send_email", _send)

    def _seen(conn, uid, logger):
        calls["mark_uid_seen"] += 1
    monkeypatch.setattr(spam_filter, "mark_uid_seen", _seen)

    real_record = spam_filter._record_processed

    def _record(processed, account_key, account_processed, msg_id):
        calls["recorded_processed"].append(msg_id)
        return real_record(processed, account_key, account_processed, msg_id)
    monkeypatch.setattr(spam_filter, "_record_processed", _record)

    def _exec(*a, **k):
        calls["execute_spam_action"] += 1
        return action_result
    monkeypatch.setattr(spam_filter, "execute_spam_action", _exec)

    def _classify(*a, **k):
        calls["classify_email"] += 1
        return ({"decision": classify_decision, "confidence": 0.99,
                 "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify)

    def _save_cmd(data):
        calls["save_command_scan_state"] += 1
    monkeypatch.setattr(spam_filter, "save_command_scan_state", _save_cmd)
    monkeypatch.setattr(spam_filter, "load_command_scan_state",
                        lambda: {"version": "1.0", "last_updated": "",
                                 "folders": {}})
    monkeypatch.setattr(
        spam_filter, "fetch_command_scan_uids",
        lambda conn, folder, logger, stored: (list(command_uids or []),
                                              cmd_state_update))
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: list(uids or []))
    monkeypatch.setattr(spam_filter, "fetch_message_id",
                        lambda conn, uid, logger: "")
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"raw")
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_data or {}))

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())

    spam_filter.run_filter(force=True)
    return calls


def _base_msg(**over):
    md = {
        "message_id": "<m-1@x>", "from_email": "owner@example.com",
        "from_display_name": "Owner", "subject": "Weekly digest",
        "plain_text_body": "hello", "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "list_unsubscribe": "", "received_headers": [],
        "received_headers_first_3": [], "_mime_msg": None,
    }
    md.update(over)
    return md


def _plain_owner_msg(subject="Weekly digest", mid="<m-1@x>"):
    return _base_msg(subject=subject, message_id=mid)


# --------------------------------------------------------------------------- #
# E1 — Dry Run never persists the command-scan watermark; live run does.
# --------------------------------------------------------------------------- #
def test_e1_dry_run_writes_no_command_scan_state(monkeypatch):
    calls = _harness(
        monkeypatch, dry_run=True, command_uids=[b"7"],
        msg_data=_plain_owner_msg(),
        cmd_state_update={"uidvalidity": 1, "uid_watermark": 7})
    assert calls["save_command_scan_state"] == 0, (
        "Dry Run must not write command_scan_state.json (E1/S4)")


def test_e1_live_run_persists_command_scan_state(monkeypatch):
    calls = _harness(
        monkeypatch, dry_run=False, command_uids=[b"7"],
        msg_data=_plain_owner_msg(),
        cmd_state_update={"uidvalidity": 1, "uid_watermark": 7})
    assert calls["save_command_scan_state"] >= 1, (
        "a live tick must advance + persist the watermark")


# --------------------------------------------------------------------------- #
# E2 — Train-folder body derivation prefers HTML-visible text.
# --------------------------------------------------------------------------- #
def test_e2_train_folder_learns_from_html_body(monkeypatch):
    captured = {}

    class _Conn:
        def select(self, folder):
            return ("OK", [b""])

        def uid(self, cmd, *a):
            if cmd == "SEARCH":
                return ("OK", [b"1"])
            return ("OK", [b""])

        def expunge(self):
            return ("OK", [b""])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"raw")
    # Plain part is an innocuous decoy; the REAL payload is only in the HTML.
    monkeypatch.setattr(
        spam_filter, "extract_email_data",
        lambda raw, own_hosts=None: {
            "from_header_raw": "Spammer <s@evil.test>",
            "from_email": "s@evil.test", "subject": "hi",
            "plain_text_body": "innocuous decoy meeting notes",
            "html_body": "<html><body><p>WIN A FREE IPHONE NOW</p></body></html>",
        })

    def _submit(fwd_data, config, account, logger):
        captured["body"] = fwd_data["original_body"]
        return True
    monkeypatch.setattr(spam_filter, "submit_spam_example", _submit)

    spam_filter.scan_train_folder(
        _Conn(), {"name": "A", "username": "owner@example.com",
                  "imap_host": "imap.x"}, {"smtp": {}}, _LOG)
    assert "WIN A FREE IPHONE NOW" in captured["body"], (
        "Train learner must read the HTML-derived visible text (E2)")
    assert "innocuous decoy" not in captured["body"]


# --------------------------------------------------------------------------- #
# E3 — no FP self-mail subject embeds the original spam subject; the analysis
#      body names it on an "About:" line instead.
# --------------------------------------------------------------------------- #
def test_e3_no_fp_subject_embeds_original_subject():
    import inspect
    src = inspect.getsource(spam_filter.run_filter)
    assert "False Positive Analysis [{sfid}] — " not in src
    assert "original_subject', '')[:40]}" not in src
    assert "original_subject'][:50]}" not in src
    # The analysis body names the original subject on an About: line instead.
    assert 'About: "{fwd_data[\'original_subject\']}"' in src


# --------------------------------------------------------------------------- #
# E5 — every registered self-mail opening is caught by _is_own_outgoing_mail;
#      body-constant openings must stay registered (drift guard).
# --------------------------------------------------------------------------- #
_OWNER_ACCT = {"name": "A", "username": "owner@example.com"}
_OWNER_CFG = {"smtp": {"username": "owner@example.com",
                       "from_address": "owner@example.com"},
              "accounts": [_OWNER_ACCT]}


@pytest.mark.parametrize("marker", spam_filter._OWN_OUTGOING_BODY_MARKERS)
def test_e5_each_marker_is_recognized_as_own_mail(marker):
    md = {"from_email": "owner@example.com",
          "plain_text_body": marker + " ... rest of body"}
    assert spam_filter._is_own_outgoing_mail(md, _OWNER_ACCT, _OWNER_CFG) is True


def test_e5_non_owner_from_is_never_own_mail():
    # Same marker text but a third-party From must NOT be treated as our mail.
    md = {"from_email": "stranger@evil.test",
          "plain_text_body": spam_filter._OWN_OUTGOING_BODY_MARKERS[0] + " x"}
    assert spam_filter._is_own_outgoing_mail(md, _OWNER_ACCT, _OWNER_CFG) is False


def test_e5_body_constants_still_start_with_a_registered_marker():
    # If a body-copy edit changes an opening without updating the marker tuple,
    # this pins it so the type can't silently ship unprotected.
    markers = spam_filter._OWN_OUTGOING_BODY_MARKERS
    for const_name in ("_FP_ANALYSIS_FAILED_BODY", "_FP_FOLLOWUP_FAILED_BODY",
                       "_FP_APPLY_FAILED_BODY", "_BLOCK_APPLY_FAILED_BODY",
                       "_REFINEMENT_RETIRED_BODY", "_SFID_UNREADABLE_REPLY_BODY",
                       "_MWR_UNREADABLE_REPLY_BODY",
                       "_FP_FORWARDED_ANALYSIS_BODY",
                       "_BLACKLIST_REMOVE_RULE_SKIPPED_BODY"):
        body = getattr(spam_filter, const_name)
        assert any(body.startswith(m) for m in markers), (
            f"{const_name} opening is not a registered self-mail marker")


# --------------------------------------------------------------------------- #
# E6 — Remove-from-Blacklist skips a rule-owned entry (honest ack, no delete).
# --------------------------------------------------------------------------- #
def _remove_bl_msg():
    return _base_msg(
        message_id="<rm-1@x>", subject="Fwd: Remove from Blacklist",
        plain_text_body="From: Blocked <blocked@sender.test>\n\nspam")


def _patch_fwd(monkeypatch):
    monkeypatch.setattr(spam_filter, "parse_forwarded_email", lambda *a, **k: {
        "user_explanation": "", "original_from": "Blocked <blocked@sender.test>",
        "original_subject": "spam", "original_date": "", "original_body": "x",
        "_source": "test", "_divider_kind": "test", "_candidates": [],
        "_sender_conflict": None})


def test_e6_rule_owned_entry_is_not_deleted(monkeypatch):
    _patch_fwd(monkeypatch)
    bl = {"addresses": [{"value": "blocked@sender.test", "scope": "all",
                         "provenance": [{"id": "R-1", "scope": "all"}]}],
          "domains": [], "display_names": [], "subject_keywords": [],
          "_addresses_set": set(), "_domains_set": set(),
          "_display_names_set": set()}
    calls = _harness(monkeypatch, command_uids=[b"1"], msg_data=_remove_bl_msg(),
                     blacklist=bl,
                     cmd_state_update={"uidvalidity": 1, "uid_watermark": 1})
    assert calls["save_blacklist"] == 0, "a rule-owned entry must not be deleted"
    subjects = [s for (s, b) in calls["send_email_args"]]
    bodies = [b for (s, b) in calls["send_email_args"]]
    assert any("Managed by a Rule" in s for s in subjects)
    assert any(b.startswith("MailWarden kept this sender blocked.")
               for b in bodies)
    assert not any("evaluated by the spam classifier" in b for b in bodies)


def test_e6_typed_entry_is_deleted(monkeypatch):
    _patch_fwd(monkeypatch)
    bl = {"addresses": ["blocked@sender.test"], "domains": [],
          "display_names": [], "subject_keywords": [],
          "_addresses_set": set(), "_domains_set": set(),
          "_display_names_set": set()}
    calls = _harness(monkeypatch, command_uids=[b"1"], msg_data=_remove_bl_msg(),
                     blacklist=bl,
                     cmd_state_update={"uidvalidity": 1, "uid_watermark": 1})
    assert calls["save_blacklist"] == 1, "a hand-typed entry is deleted as before"
    bodies = [b for (s, b) in calls["send_email_args"]]
    assert any(b.startswith("The following entries have been removed")
               for b in bodies)
    # No rule entry was involved, so the plain classifier claim stands.
    assert any("evaluated by the spam classifier" in b for b in bodies)


def test_e6_mixed_typed_removed_but_rule_entry_kept(monkeypatch):
    """Review fix: hand-typed display name removed + rule-owned address kept.
    The success ack must confirm the removal AND carry the honest rule note —
    never the unconditional 'evaluated by the spam classifier' claim, because
    the surviving rule-owned entry still blocks this sender pre-classifier."""
    _patch_fwd(monkeypatch)
    bl = {"addresses": [{"value": "blocked@sender.test", "scope": "all",
                         "provenance": [{"id": "R-1", "scope": "all"}]}],
          "domains": [],
          "display_names": ["Blocked"],   # hand-typed, same sender's name
          "subject_keywords": [],
          "_addresses_set": set(), "_domains_set": set(),
          "_display_names_set": set()}
    calls = _harness(monkeypatch, command_uids=[b"1"], msg_data=_remove_bl_msg(),
                     blacklist=bl,
                     cmd_state_update={"uidvalidity": 1, "uid_watermark": 1})
    # The typed display name WAS removed (one save)...
    assert calls["save_blacklist"] == 1
    subjects = [s for (s, b) in calls["send_email_args"]]
    bodies = [b for (s, b) in calls["send_email_args"]]
    assert any("Blacklist Removal Confirmed" in s for s in subjects)
    body = next(b for b in bodies
                if b.startswith("The following entries have been removed"))
    assert "Display name removed: Blocked" in body
    # ...but the rule-owned address survives, so the ack carries the rule note
    assert "MailWarden kept this sender blocked." in body
    assert "Unwanted Categories" in body
    # and never the false unconditional claim.
    assert "evaluated by the spam classifier" not in body


# --------------------------------------------------------------------------- #
# E7 — _teach_legit_blacklist_warning: curate-hit, blacklist-precedence, no-hit.
# --------------------------------------------------------------------------- #
def _empty_bl():
    return {"addresses": [], "domains": [], "display_names": [],
            "subject_keywords": [], "_addresses_set": set(),
            "_domains_set": set(), "_display_names_set": set()}


def _curate_signals(kind="domain", value="news.test"):
    return {"ai_refinements": [{
        "id": "R-9", "rule_class": "curate", "status": "active",
        "scope": "all", "headline": "No retailer newsletters",
        "enforcement": "mixed",
        "deterministic_entries": [{"kind": kind, "value": value}],
    }]}


def test_e7_curate_rule_hit_returns_warning():
    warn = spam_filter._teach_legit_blacklist_warning(
        "News <hello@news.test>", _empty_bl(),
        account_name="owner@example.com", signals=_curate_signals())
    assert "No retailer newsletters" in warn
    assert "Signal History" in warn


def test_e7_blacklist_takes_precedence_over_curate():
    bl = _empty_bl()
    bl["addresses"] = ["hello@news.test"]
    bl["_addresses_set"] = {"hello@news.test"}
    warn = spam_filter._teach_legit_blacklist_warning(
        "News <hello@news.test>", bl, account_name="owner@example.com",
        signals=_curate_signals(kind="address", value="hello@news.test"))
    # The blacklist (typed) branch wins — not the curate copy.
    assert warn == spam_filter._TEACH_LEGIT_BL_WARNING_TYPED


def test_e7_no_hit_returns_empty():
    warn = spam_filter._teach_legit_blacklist_warning(
        "Someone <a@unrelated.test>", _empty_bl(),
        account_name="owner@example.com", signals=_curate_signals())
    assert warn == ""


def test_e7_signature_is_the_wired_contract():
    # Writer D wires the dashboard call against this exact 4-arg signature.
    import inspect
    sig = inspect.signature(spam_filter._teach_legit_blacklist_warning)
    assert list(sig.parameters) == ["from_header", "blacklist",
                                    "account_name", "signals"]


# --------------------------------------------------------------------------- #
# E8 — _expunge_one no longer self-reinforces its own deferrals across ticks.
# --------------------------------------------------------------------------- #
class _NonUidplusConn:
    """Server without UIDPLUS; a FOREIGN \\Deleted message (99) is always
    present, and our own \\Deleted UIDs accumulate as we flag them."""

    def __init__(self, foreign=("99",)):
        self.capabilities = ()
        self.deleted = set(foreign)       # currently-\Deleted UIDs on server
        self.expunged = False

    def uid(self, cmd, *a):
        if cmd == "SEARCH":
            return ("OK", [" ".join(sorted(self.deleted)).encode()])
        return ("OK", [b""])

    def expunge(self):
        self.expunged = True
        self.deleted.clear()
        return ("OK", [b""])

    def status(self, folder, key):
        return ("OK", [f"{folder} (UIDVALIDITY 111)".encode()])


def test_e8_self_reinforcement_repro_eventually_purges(monkeypatch, tmp_path):
    monkeypatch.setattr(spam_filter, "EXPUNGE_DEFERRED_PATH",
                        tmp_path / "expunge_deferred.json")
    conn = _NonUidplusConn(foreign=("99",))
    ak, folder = "owner@example.com", "INBOX"

    # Tick 1: flag UID 1; a foreign \Deleted (99) is present -> defer + remember.
    conn.deleted.add("1")
    spam_filter._expunge_one(conn, b"1", _LOG, account_key=ak, folder=folder)
    assert conn.expunged is False
    assert "1" in conn.deleted  # left flagged

    # The foreign client finishes and its \Deleted message goes away.
    conn.deleted.discard("99")

    # Tick 2: flag UID 2. Now every \Deleted message is ours ({1} remembered +
    # {2} current) — the OLD code deferred forever here; E8 must purge.
    conn.deleted.add("2")
    spam_filter._expunge_one(conn, b"2", _LOG, account_key=ak, folder=folder)
    assert conn.expunged is True, (
        "once only our own deferred \\Deleted mail remains, E8 must purge "
        "(no self-reinforcing deferral)")
    assert conn.deleted == set()


def test_e8_still_defers_when_genuinely_foreign_deleted_present(monkeypatch,
                                                                tmp_path):
    monkeypatch.setattr(spam_filter, "EXPUNGE_DEFERRED_PATH",
                        tmp_path / "expunge_deferred.json")
    conn = _NonUidplusConn(foreign=("99",))
    conn.deleted.add("1")
    spam_filter._expunge_one(conn, b"1", _LOG,
                             account_key="owner@example.com", folder="INBOX")
    assert conn.expunged is False, (
        "a genuinely foreign \\Deleted message must still block the purge")


# --------------------------------------------------------------------------- #
# E4 — auth-failed owner reply to a REAL pending report stays in inbox;
#      an unknown token falls through to classification.
# --------------------------------------------------------------------------- #
def _delivered_mime():
    """A real parsed message with a foreign-MX Received chain, as delivered mail
    always carries. Keeps an owner-sent reply out of the owner-mail exemption's
    absent-host fallback (which only applies when there is NO Received evidence,
    e.g. IMAP APPEND), so a non-command owner reply still reaches classification
    exactly as these tests expect."""
    return _email.message_from_string(
        "Received: from mx.provider.test (mx.provider.test [203.0.113.9]) "
        "by mx.provider.test with esmtp id d1 for <owner@example.com>\n"
        "\nbody\n")


def _mwr_reply(token="tok123", mid="<mwr-1@x>"):
    return _base_msg(
        message_id=mid, subject=f"Re: MailWarden Report [MWR-{token}]",
        plain_text_body="APPROVE 1", _mime_msg=_delivered_mime())


def test_e4_authfail_reply_to_real_report_not_classified(monkeypatch):
    calls = _harness(
        monkeypatch, command_uids=[b"1"], uids=[b"1"], msg_data=_mwr_reply(),
        auth_ok=False, approvals_store={"tok123": {"created": "2026-07-07"}},
        cmd_state_update={"uidvalidity": 1, "uid_watermark": 1})
    assert calls["classify_email"] == 0, (
        "a genuine owner reply to a real report must not be classified/junked")
    assert calls["execute_spam_action"] == 0


def test_e4_authfail_reply_with_unknown_token_is_classified(monkeypatch):
    calls = _harness(
        monkeypatch, command_uids=[b"1"], uids=[b"1"],
        msg_data=_mwr_reply(token="forged"),
        auth_ok=False, approvals_store={"tok123": {"created": "2026-07-07"}},
        cmd_state_update={"uidvalidity": 1, "uid_watermark": 1})
    assert calls["classify_email"] == 1, (
        "a forged/unknown token keeps today's classify behavior")


# --------------------------------------------------------------------------- #
# E9 — a tagged NON-command MWR message that falls through to classification
#      must NOT have been precommitted; when its junk move FAILS it stays out
#      of processed_ids so it is retried.
# --------------------------------------------------------------------------- #
def _mwr_noncommand(mid="<mwr-nc@x>"):
    # neither APPROVE nor KEEP/DROP/RESTORE
    return _base_msg(message_id=mid,
                     subject="Re: MailWarden Report [MWR-tok123]",
                     plain_text_body="thanks, looks good!",
                     _mime_msg=_delivered_mime())


def test_e9_tagged_noncommand_failed_move_is_retried(monkeypatch):
    calls = _harness(
        monkeypatch, command_uids=[b"1"], uids=[b"1"], msg_data=_mwr_noncommand(),
        approvals_store={"tok123": {"created": "2026-07-07"}},
        cmd_state_update={"uidvalidity": 1, "uid_watermark": 1},
        classify_decision="SPAM", action_result="[MOVE FAILED to Junk]")
    # It fell through to classification (not a command)...
    assert calls["classify_email"] == 1
    # ...and because the junk move FAILED it is NOT recorded processed (E9 +
    # the pre-existing failed-move retry contract), so a later tick retries it.
    assert "<mwr-nc@x>" not in calls["recorded_processed"], (
        "a tagged non-command whose junk move failed must stay retryable")

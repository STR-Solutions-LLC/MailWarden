#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""N1 + N2 — command-handler paths over dict list entries.

N1: the Blacklist-Address command deduped with a raw ``{a.lower() for a in
    bl_data["addresses"]}`` which raises AttributeError on a scoped dict entry
    ({"value","scope"} since a02d7ea). The handler now extracts the value
    tolerantly, so a seeded dict entry neither crashes nor breaks dedup.

N2: an explicit "Whitelist" command for an address already present only as an
    APPROVE-sourced dict entry now UPGRADES it to a plain-string (hand-typed
    trump) instead of reporting "already on the whitelist. No changes made".

Both are exercised through the real run_filter command dispatch (every IO/
network call mocked), so the fix is verified on the actual handler path.
"""
import json
import logging as _logging
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

_LOGGER = _logging.getLogger("test_command_handler")
_LOGGER.addHandler(_logging.NullHandler())

_ACCOUNT_KEY = "owner@example.com"


def _msg(subject="Whitelist Sender", body="forwarded body"):
    return {
        "message_id": "<cmd-1@ex.com>", "from_email": _ACCOUNT_KEY,
        "from_display_name": "Owner", "subject": subject,
        "plain_text_body": body, "html_body": "", "reply_to": "",
        "auth_results": "", "received_spf": "", "dkim_signature": "",
        "x_spam_score": "", "x_spam_flag": "", "x_spam_status": "",
        "received_headers": [], "received_headers_first_3": [],
        "from_header_raw": f"Owner <{_ACCOUNT_KEY}>", "_mime_msg": None,
    }


def _drive(monkeypatch, tmp_path, *, command, resolve_addr=None,
           wl_seed=None, bl_seed=None, msg_subject="Whitelist Sender",
           msg_body="forwarded body"):
    """Drive run_filter over a single command message. Returns captured
    {"emails": [(subject, body)], "saved_blacklists": [dict],
     "wl_path": Path}."""
    captured = {"emails": [], "saved_blacklists": [],
                "wl_path": tmp_path / "whitelist.json"}

    cfg = {
        "filter": {"dry_run": False, "confidence_threshold": 0.85,
                   "max_emails_per_run": 1000, "log_level": "INFO"},
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
    uids = {b"1": _msg(subject=msg_subject, body=msg_body)}

    monkeypatch.setattr(spam_filter, "WHITELIST_PATH", captured["wl_path"])
    monkeypatch.setattr(spam_filter, "BLACKLIST_PATH", tmp_path / "blacklist.json")

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_dry_run_verdicts", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "persist_dry_run_verdicts", lambda dv: None)
    monkeypatch.setattr(spam_filter, "load_signals",
                        lambda: {"signals": {}, "ai_refinements": []})

    def _load_wl(logger):
        base = {"domains": [], "addresses": [], "_addresses_set": set(),
                "_addresses_approve_set": set(), "_domains_set": set()}
        if wl_seed:
            base = {k: (list(v) if isinstance(v, list) else set(v)
                        if isinstance(v, set) else v)
                    for k, v in wl_seed.items()}
        return base
    monkeypatch.setattr(spam_filter, "load_whitelist", _load_wl)

    def _load_bl(logger):
        if bl_seed is not None:
            # fresh deep-ish copy so a mutation doesn't leak across calls
            return json.loads(json.dumps(bl_seed))
        return {"addresses": [], "domains": [], "display_names": [],
                "subject_keywords": []}
    monkeypatch.setattr(spam_filter, "load_blacklist", _load_bl)
    monkeypatch.setattr(spam_filter, "save_blacklist",
                        lambda bl: captured["saved_blacklists"].append(bl))

    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": [], "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "detect_conflicts", lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage", lambda: {})
    monkeypatch.setattr(spam_filter, "new_token_delta", lambda: {})
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: {"conversations": []})
    monkeypatch.setattr(spam_filter, "persist_progress", lambda p, tu, td: None)
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "prune_decisions_log", lambda: None)
    monkeypatch.setattr(spam_filter, "prune_pending_signals", lambda: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "scan_train_folder",
                        lambda conn, account, config, logger: None)
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed", lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "log_decision", lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "mark_uid_seen", lambda conn, uid, logger: None)
    monkeypatch.setattr(spam_filter, "_command_sender_is_owner", lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "_command_auth_ok", lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "_notify_unverified_command", lambda *a, **k: None)

    monkeypatch.setattr(spam_filter, "detect_email_command", lambda subject: command)
    monkeypatch.setattr(spam_filter, "parse_forwarded_email",
                        lambda *a, **k: {"original_from": f"S <{resolve_addr}>",
                                         "_divider_kind": "forward", "_source": "x",
                                         "original_subject": "", "_sender_conflict": None})
    monkeypatch.setattr(spam_filter, "_resolve_spam_sender",
                        lambda fwd, acct, cfg_: {"address": resolve_addr,
                                                 "refused": False, "skipped": False})

    def _send(config, subject, body, logger, **k):
        captured["emails"].append((subject, body))
    monkeypatch.setattr(spam_filter, "send_email", _send)

    def _classify(*a, **k):
        return ({"decision": "NOT_SPAM", "confidence": 0.0, "signals_hit": []}, None)
    monkeypatch.setattr(spam_filter, "classify_email", _classify)
    monkeypatch.setattr(spam_filter, "execute_spam_action", lambda *a, **k: "moved")

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: list(uids))
    monkeypatch.setattr(spam_filter, "fetch_message_id",
                        lambda conn, uid, logger: uids[uid]["message_id"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: b"RAW")
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(uids[b"1"]))

    spam_filter.run_filter(force=True)
    return captured


# ── N2: Whitelist command upgrades an APPROVE-sourced entry ────────────────

def test_whitelist_command_upgrades_approve_entry_to_plain_string(monkeypatch, tmp_path):
    seed = {"domains": [], "_domains_set": set(),
            "addresses": [{"value": "appr@gmail.com", "provenance": "approve"}],
            "_addresses_set": {"appr@gmail.com"},
            "_addresses_approve_set": {"appr@gmail.com"}}
    cap = _drive(monkeypatch, tmp_path, command="Whitelist",
                 resolve_addr="appr@gmail.com", wl_seed=seed)
    # The handler acknowledged an UPGRADE (not "no changes made").
    subjects_bodies = " || ".join(s + " :: " + b for s, b in cap["emails"])
    assert "Upgraded to full whitelist" in subjects_bodies
    assert "No changes made" not in subjects_bodies
    # And the on-disk entry is now a plain string (absolute trump), not a dict.
    written = json.loads(cap["wl_path"].read_text())
    assert written["addresses"] == ["appr@gmail.com"]


def test_whitelist_command_plain_string_entry_is_no_change(monkeypatch, tmp_path):
    seed = {"domains": [], "_domains_set": set(),
            "addresses": ["appr@gmail.com"],
            "_addresses_set": {"appr@gmail.com"},
            "_addresses_approve_set": set()}
    cap = _drive(monkeypatch, tmp_path, command="Whitelist",
                 resolve_addr="appr@gmail.com", wl_seed=seed)
    joined = " || ".join(s + " :: " + b for s, b in cap["emails"])
    assert "already on the whitelist. No changes made" in joined
    assert "Upgraded" not in joined
    # No write happened.
    assert not cap["wl_path"].exists()


# ── N1: Blacklist-Address command over a seeded dict entry ─────────────────

def test_blacklist_address_new_over_dict_entry_no_crash_and_appends(monkeypatch, tmp_path):
    bl = {"addresses": [{"value": "existing@vendor.com",
                         "scope": [_ACCOUNT_KEY]}],
          "domains": [], "display_names": [], "subject_keywords": []}
    cap = _drive(monkeypatch, tmp_path, command="Blacklist Address",
                 resolve_addr="newspammer@vendor.com", bl_seed=bl)
    # No AttributeError (would have crashed the handler on the dict entry).
    assert cap["saved_blacklists"], "handler must have saved the blacklist"
    saved_addrs = cap["saved_blacklists"][-1]["addresses"]
    # Dict entry preserved; new plain-string value appended.
    assert {"value": "existing@vendor.com", "scope": [_ACCOUNT_KEY]} in saved_addrs
    assert "newspammer@vendor.com" in saved_addrs
    joined = " || ".join(s for s, _ in cap["emails"])
    assert "Blacklist Address Confirmed" in joined


def test_blacklist_address_dedup_by_value_of_dict_entry(monkeypatch, tmp_path):
    bl = {"addresses": [{"value": "existing@vendor.com",
                         "scope": [_ACCOUNT_KEY]}],
          "domains": [], "display_names": [], "subject_keywords": []}
    cap = _drive(monkeypatch, tmp_path, command="Blacklist Address",
                 resolve_addr="existing@vendor.com", bl_seed=bl)
    # Dedup matched the dict entry BY VALUE -> nothing saved.
    assert cap["saved_blacklists"] == []
    joined = " :: ".join(b for _, b in cap["emails"])
    assert "already on the blacklist. No changes made" in joined


# ── Defect 1: Direct Blacklist over a seeded scoped-dict DOMAIN entry ───────
# _apply_parsed_list_entries deduped domains with a raw {d.lower() ...} that
# raises AttributeError on a scoped {"value","scope"} domain dict — the account
# scan then aborts and re-crashes every run because the command stays unseen.

def test_direct_blacklist_new_domain_over_dict_domain_entry_no_crash(monkeypatch, tmp_path):
    bl = {"addresses": [], "display_names": [], "subject_keywords": [],
          "domains": [{"value": "existing.com", "scope": [_ACCOUNT_KEY]}]}
    cap = _drive(monkeypatch, tmp_path, command="Direct Blacklist",
                 msg_subject="Blacklist", msg_body="@newdomain.com",
                 bl_seed=bl)
    # No AttributeError; the handler ran to completion and saved the addition.
    assert cap["saved_blacklists"], "handler must have saved the blacklist"
    saved_domains = cap["saved_blacklists"][-1]["domains"]
    assert {"value": "existing.com", "scope": [_ACCOUNT_KEY]} in saved_domains
    assert "newdomain.com" in saved_domains
    joined = " || ".join(s for s, _ in cap["emails"])
    assert "Blacklist Updated" in joined


def test_direct_blacklist_dedup_by_value_of_dict_domain_entry(monkeypatch, tmp_path):
    bl = {"addresses": [], "display_names": [], "subject_keywords": [],
          "domains": [{"value": "existing.com", "scope": [_ACCOUNT_KEY]}]}
    cap = _drive(monkeypatch, tmp_path, command="Direct Blacklist",
                 msg_subject="Blacklist", msg_body="@existing.com",
                 bl_seed=bl)
    # Dedup matched the dict entry BY VALUE (@-stripped) -> nothing added/saved.
    assert cap["saved_blacklists"] == []
    joined = " || ".join(b for _, b in cap["emails"])
    assert "Already present (1): @existing.com" in joined
    assert "Added (0): none" in joined

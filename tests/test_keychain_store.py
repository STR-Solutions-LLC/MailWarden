#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Keychain migration — Batch 1 tests (docs/keychain-design-plan.md §5.3, §10.1).

Scope of Batch 1: the keychain_store module (×2, byte-identical), the secrets
config block, hydrate-on-load / strip-on-save in both the GUI and engine
loaders/savers, the keychain_status.json writer, and the fail-closed preflight
in the filter + report.

CRITICAL GUARANTEE under test: the whole feature ships DARK behind
secrets.backend. While the backend is "config" (the only reachable state after
this landing) every keychain code path is inert — hydrate/strip return the input
unchanged and NO SecItem* call is reachable. Several tests below prove exactly
that (see the "dark ship" section).

The real Security.framework is absent on the dev/CI machine, so
keychain_store.available() is False here and no test ever touches the real login
keychain: the raw item ops are monkeypatched with an in-memory fake keychain.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_keychain_store.py -v
"""
import copy
import json
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import keychain_store as engine_ks  # engine-tree copy  # noqa: E402
from mailwarden_app import keychain_store as ks  # GUI-tree copy  # noqa: E402
from mailwarden_app import config_io, paths  # noqa: E402
import spam_filter  # noqa: E402
import daily_report  # noqa: E402
import utils  # noqa: E402


# ---------------------------------------------------------------------------
# In-memory fake keychain for the tests that exercise the keychain backend.
# ---------------------------------------------------------------------------
class FakeKeychain:
    def __init__(self, items=None, locked=None):
        # items: {account_key: value}; locked: set of account_keys that raise.
        self.items = dict(items or {})
        self.locked = set(locked or ())
        self.reads = []
        self.writes = []
        self.deletes = []

    def read(self, account_key, keychain=None):
        self.reads.append(account_key)
        if account_key in self.locked:
            raise ks.KeychainLocked(ks.errSecInteractionNotAllowed)
        return self.items.get(account_key)

    def write(self, account_key, label, value, keychain=None):
        self.writes.append((account_key, value))
        self.items[account_key] = value

    def delete(self, account_key, missing_ok=False, keychain=None):
        self.deletes.append(account_key)
        self.items.pop(account_key, None)


@pytest.fixture
def fake_kc(monkeypatch):
    fk = FakeKeychain()
    # Patch BOTH copies (engine + GUI import the same object here, but be
    # explicit so a future divergence is caught).
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "read_secret", fk.read)
        monkeypatch.setattr(mod, "write_secret", fk.write)
        monkeypatch.setattr(mod, "delete_secret", fk.delete)
        monkeypatch.setattr(mod, "available", lambda: True)
    return fk


def _keychain_config(**secret_values):
    """A config with backend=keychain, migration complete, and every secret
    field set to the sentinel unless overridden."""
    cfg = {
        "anthropic": {"api_key": secret_values.get("api_key", ks.SENTINEL)},
        "smtp": {"host": "smtp.host.com", "username": "me@host.com",
                 "password": secret_values.get("smtp", ks.SENTINEL)},
        "accounts": [{"imap_host": "imap.host.com", "username": "me@host.com",
                      "password": secret_values.get("imap", ks.SENTINEL)}],
        "secrets": {"backend": "keychain",
                    "migration": {"state": "complete"}},
    }
    return cfg


# ---------------------------------------------------------------------------
# Drift guard — the two module copies must be byte-identical (§2).
# ---------------------------------------------------------------------------
def test_module_copies_byte_identical():
    gui = os.path.join(APP, "mailwarden_app", "keychain_store.py")
    eng = os.path.join(SRC, "keychain_store.py")
    with open(gui, "rb") as f:
        gui_bytes = f.read()
    with open(eng, "rb") as f:
        eng_bytes = f.read()
    assert gui_bytes == eng_bytes, "keychain_store.py copies have drifted"


# ---------------------------------------------------------------------------
# Account-key derivation, incl. the shared-mailbox edge (§3).
# ---------------------------------------------------------------------------
def test_account_key_derivation():
    assert ks.api_key_account() == "anthropic-api-key"
    assert ks.self_mail_account() == "self-mail-secret"
    assert ks.imap_account("IMAP.Host.COM", "Me@Host.com") == "imap|imap.host.com|me@host.com"
    assert ks.smtp_account("SMTP.x", "U@x") == "smtp|smtp.x|u@x"


def test_shared_mailbox_derives_same_key():
    # Two accounts with the same (imap_host, username) are the same mailbox and
    # must map to ONE item key (§3).
    a = ks.imap_account("imap.host.com", "me@host.com")
    b = ks.imap_account("IMAP.HOST.COM", "  me@host.com ")
    assert a == b


# ---------------------------------------------------------------------------
# hydrate — config backend is a pure no-op; keychain backend resolves states.
# ---------------------------------------------------------------------------
def test_hydrate_config_backend_is_identity():
    cfg = {"anthropic": {"api_key": ks.SENTINEL},
           "secrets": {"backend": "config"}}
    out = ks.hydrate(cfg)
    assert out is cfg  # same object, untouched
    assert out["anthropic"]["api_key"] == ks.SENTINEL  # sentinel NOT resolved
    assert "_secret_errors" not in out


def test_hydrate_missing_secrets_block_is_config():
    cfg = {"anthropic": {"api_key": ks.SENTINEL}}
    assert ks.hydrate(cfg) is cfg
    assert cfg["anthropic"]["api_key"] == ks.SENTINEL


def test_hydrate_keychain_all_ok(fake_kc):
    fake_kc.items = {
        ks.api_key_account(): "sk-real-key",
        ks.smtp_account("smtp.host.com", "me@host.com"): "smtp-pw",
        ks.imap_account("imap.host.com", "me@host.com"): "imap-pw",
    }
    cfg = ks.hydrate(_keychain_config())
    assert cfg["anthropic"]["api_key"] == "sk-real-key"
    assert cfg["smtp"]["password"] == "smtp-pw"
    assert cfg["accounts"][0]["password"] == "imap-pw"
    assert cfg["_secret_errors"] == []


def test_hydrate_keychain_mixed_missing_and_locked(fake_kc):
    fake_kc.items = {ks.api_key_account(): "sk-real-key"}  # smtp missing
    fake_kc.locked = {ks.imap_account("imap.host.com", "me@host.com")}
    cfg = ks.hydrate(_keychain_config())
    assert cfg["anthropic"]["api_key"] == "sk-real-key"
    # missing + locked leave the sentinel in place and record an error each
    assert cfg["smtp"]["password"] == ks.SENTINEL
    assert cfg["accounts"][0]["password"] == ks.SENTINEL
    reasons = {(e["key"], e["reason"]) for e in cfg["_secret_errors"]}
    assert (ks.smtp_account("smtp.host.com", "me@host.com"), "missing") in reasons
    assert (ks.imap_account("imap.host.com", "me@host.com"), "locked") in reasons


def test_hydrate_empty_secret_not_read(fake_kc):
    # An empty API key (no key configured) is never a keychain item — hydrate
    # must leave "" untouched and not record it as an error.
    cfg = _keychain_config(api_key="")
    cfg = ks.hydrate(cfg)
    assert cfg["anthropic"]["api_key"] == ""
    assert all(e["key"] != ks.api_key_account() for e in cfg["_secret_errors"])


def test_hydrate_shadow_mode_prefers_keychain_falls_back(fake_kc):
    # During migration (state != complete) plaintext is still present; hydrate
    # prefers the keychain value and falls back to plaintext on a read failure —
    # but EVERY failed read is still recorded (shadow-flagged) so tick-verify
    # can only pass when the keychain genuinely served every secret (defect 2).
    cfg = {
        "anthropic": {"api_key": "plaintext-key"},
        "smtp": {"host": "s", "username": "u", "password": "plain-smtp"},
        "accounts": [{"imap_host": "h", "username": "u", "password": "plain-imap"}],
        "secrets": {"backend": "keychain", "migration": {"state": "items_written"}},
    }
    fake_kc.items = {ks.api_key_account(): "kc-key"}  # only api key in keychain
    out = ks.hydrate(cfg)
    assert out["anthropic"]["api_key"] == "kc-key"        # keychain wins
    assert out["smtp"]["password"] == "plain-smtp"        # fallback to plaintext
    assert out["accounts"][0]["password"] == "plain-imap"
    # The two failed reads are recorded as SHADOW failures (fallback worked).
    recorded = {(e["key"], e["reason"], e["shadow"]) for e in out["_secret_errors"]}
    assert (ks.smtp_account("s", "u"), "missing", True) in recorded
    assert (ks.imap_account("h", "u"), "missing", True) in recorded
    assert len(out["_secret_errors"]) == 2
    # No HARD errors — the run may proceed…
    assert ks.hard_secret_errors(out) == []
    # …but the status record must say the keychain did NOT fully work.
    rec = ks.status_record(out, "run-filter")
    assert rec["ok"] is False
    assert rec["shadow_fallback"] is True


def test_hydrate_shadow_mode_all_reads_succeed_is_ok(fake_kc):
    # Shadow window with every keychain read succeeding: no errors, ok:true —
    # the ONLY state tick-verify may advance from.
    cfg = {
        "anthropic": {"api_key": "plaintext-key"},
        "smtp": {"host": "s", "username": "u", "password": "plain-smtp"},
        "accounts": [{"imap_host": "h", "username": "u", "password": "plain-imap"}],
        "secrets": {"backend": "keychain", "migration": {"state": "items_written"}},
    }
    fake_kc.items = {
        ks.api_key_account(): "kc-key",
        ks.smtp_account("s", "u"): "kc-smtp",
        ks.imap_account("h", "u"): "kc-imap",
    }
    out = ks.hydrate(cfg)
    assert out["anthropic"]["api_key"] == "kc-key"
    assert out["smtp"]["password"] == "kc-smtp"
    assert out["accounts"][0]["password"] == "kc-imap"
    assert out["_secret_errors"] == []
    rec = ks.status_record(out, "run-filter")
    assert rec["ok"] is True
    assert rec["shadow_fallback"] is False


def test_hydrate_shadow_sentinel_failure_is_hard(fake_kc):
    # A SENTINEL field whose read fails has no fallback anywhere — even in the
    # shadow window that is a HARD (fail-closed) error, never shadow-flagged.
    cfg = {
        "anthropic": {"api_key": ks.SENTINEL},  # already sentinelized
        "smtp": {"host": "s", "username": "u", "password": "plain-smtp"},
        "accounts": [],
        "secrets": {"backend": "keychain", "migration": {"state": "items_written"}},
    }
    fake_kc.items = {ks.smtp_account("s", "u"): "kc-smtp"}  # api key missing
    out = ks.hydrate(cfg)
    hard = ks.hard_secret_errors(out)
    assert [(e["key"], e["reason"]) for e in hard] == \
        [(ks.api_key_account(), "missing")]


def test_status_record_plain_errors_have_own_visibility():
    # reason "error" entries must appear under their own key (not swallowed,
    # not misfiled under missing/locked) so the Batch-3 banner can categorize.
    cfg = {"secrets": {"backend": "keychain", "migration": {"state": "complete"}},
           "_secret_errors": [
               {"key": "anthropic-api-key", "reason": "error", "shadow": False},
               {"key": "smtp|s|u", "reason": "locked", "shadow": False},
               {"key": "imap|h|u", "reason": "missing", "shadow": False},
           ]}
    rec = ks.status_record(cfg, "run-filter")
    assert rec["ok"] is False
    assert rec["errors"] == ["anthropic-api-key"]
    assert rec["missing"] == ["imap|h|u"]
    assert rec["locked"] is True


# ---------------------------------------------------------------------------
# strip_for_save — config backend no-op; keychain backend sentinelizes.
# ---------------------------------------------------------------------------
def test_strip_config_backend_is_identity():
    cfg = {"anthropic": {"api_key": "sk-real"}, "secrets": {"backend": "config"}}
    out = ks.strip_for_save(cfg)
    assert out is cfg
    assert out["anthropic"]["api_key"] == "sk-real"  # untouched


def test_strip_keychain_sentinelizes_and_drops_underscore_keys():
    cfg = _keychain_config(api_key="sk-real", smtp="smtp-pw", imap="imap-pw")
    cfg["self_mail_secret"] = "deadbeef"
    cfg["_secret_errors"] = [{"key": "x", "reason": "missing"}]
    out = ks.strip_for_save(cfg)
    assert out is not cfg  # a copy — the in-memory dict is untouched
    assert cfg["anthropic"]["api_key"] == "sk-real"  # original preserved
    assert out["anthropic"]["api_key"] == ks.SENTINEL
    assert out["smtp"]["password"] == ks.SENTINEL
    assert out["accounts"][0]["password"] == ks.SENTINEL
    assert out["self_mail_secret"] == ks.SENTINEL
    assert "_secret_errors" not in out


def test_strip_keychain_leaves_empty_and_existing_sentinel():
    cfg = _keychain_config(api_key="", smtp=ks.SENTINEL, imap="real")
    out = ks.strip_for_save(cfg)
    assert out["anthropic"]["api_key"] == ""          # empty stays empty
    assert out["smtp"]["password"] == ks.SENTINEL     # sentinel stays sentinel
    assert out["accounts"][0]["password"] == ks.SENTINEL


def test_strip_shadow_window_preserves_plaintext():
    # DEFECT 1: while migration.state != "complete" a save must NOT sentinelize —
    # plaintext is the §6.2 fallback that keeps filtering alive if the launchd
    # keychain read fails before tick verification. Only the in-memory
    # underscore keys are dropped.
    for state in ("none", "items_written", "exec_verified", "tick_verified",
                  "failed:exec_verify"):
        cfg = _keychain_config(api_key="sk-real", smtp="smtp-pw", imap="imap-pw")
        cfg["secrets"]["migration"]["state"] = state
        cfg["self_mail_secret"] = "deadbeef"
        cfg["_secret_errors"] = [{"key": "x", "reason": "missing", "shadow": True}]
        out = ks.strip_for_save(cfg)
        assert out["anthropic"]["api_key"] == "sk-real", state
        assert out["smtp"]["password"] == "smtp-pw", state
        assert out["accounts"][0]["password"] == "imap-pw", state
        assert out["self_mail_secret"] == "deadbeef", state
        assert "_secret_errors" not in out, state  # _-keys still dropped


def test_strip_shadow_window_engine_save_preserves_plaintext():
    # Same guarantee through the ENGINE's real writer (save_config_atomic): the
    # save that happens while backend is already "keychain" but migration is
    # still mid-flight must leave the plaintext fallback in config.json.
    import tempfile
    cfg = _keychain_config(api_key="sk-KEEP-ME", smtp="SMTP-KEEP", imap="IMAP-KEEP")
    cfg["secrets"]["migration"]["state"] = "items_written"
    with tempfile.TemporaryDirectory() as d:
        from pathlib import Path
        path = Path(d) / "config.json"
        spam_filter.save_config_atomic(cfg, path)
        on_disk = json.loads(path.read_text())
    assert on_disk["anthropic"]["api_key"] == "sk-KEEP-ME"
    assert on_disk["smtp"]["password"] == "SMTP-KEEP"
    assert on_disk["accounts"][0]["password"] == "IMAP-KEEP"


def test_strip_complete_state_sentinelizes():
    # At state "complete" (step 4's scrub) the same save DOES sentinelize.
    cfg = _keychain_config(api_key="sk-real", smtp="smtp-pw", imap="imap-pw")
    assert cfg["secrets"]["migration"]["state"] == "complete"
    out = ks.strip_for_save(cfg)
    assert out["anthropic"]["api_key"] == ks.SENTINEL
    assert out["smtp"]["password"] == ks.SENTINEL
    assert out["accounts"][0]["password"] == ks.SENTINEL


# ---------------------------------------------------------------------------
# Config integration — secrets block back-fill, and the byte-identical
# guarantee through the real GUI + engine save paths at config backend.
# ---------------------------------------------------------------------------
def test_deep_merge_backfills_secrets_block(tmp_path, monkeypatch):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps({"accounts": [], "anthropic": {"api_key": ""}}))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    loaded = config_io.load_config()
    assert loaded["secrets"]["backend"] == "config"
    assert loaded["secrets"]["migration"]["state"] == "none"


def test_gui_save_config_byte_identical_at_config_backend(tmp_path, monkeypatch):
    cfgfile = tmp_path / "config.json"
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    cfg = copy.deepcopy(config_io.DEFAULT_CONFIG)
    cfg["anthropic"]["api_key"] = "sk-plaintext"
    cfg["accounts"] = [config_io.new_account_entry(
        "A", "imap.h", 993, "u@h", "imap-pw", "Junk")]
    config_io.save_config(cfg)
    on_disk = json.loads(cfgfile.read_text())
    # Config backend: the plaintext is written verbatim (unchanged from today).
    assert on_disk["anthropic"]["api_key"] == "sk-plaintext"
    assert on_disk["accounts"][0]["password"] == "imap-pw"


def test_engine_eula_merge_save_strips_plaintext_under_keychain():
    # The engine's sole config writer (save_config_atomic, the EULA-merge path)
    # must never land a real password on disk once backend == keychain (§5.3).
    import tempfile
    cfg = _keychain_config()
    # Simulate a hydrated in-memory config carrying REAL secret values.
    cfg["anthropic"]["api_key"] = "sk-SECRET-KEY"
    cfg["accounts"][0]["password"] = "IMAP-SECRET"
    cfg["smtp"]["password"] = "SMTP-SECRET"
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "config.json")
        from pathlib import Path
        spam_filter.save_config_atomic(cfg, Path(path))
        text = Path(path).read_text()
    for secret in ("sk-SECRET-KEY", "IMAP-SECRET", "SMTP-SECRET"):
        assert secret not in text, f"plaintext {secret!r} leaked to disk"
    assert ks.SENTINEL in text


# ---------------------------------------------------------------------------
# DARK SHIP PROOF — no SecItem* reachable while backend == "config".
# ---------------------------------------------------------------------------
def _boom(*a, **k):
    raise AssertionError("a raw keychain op was called at config backend")


def test_dark_ship_hydrate_strip_never_call_raw_ops(monkeypatch):
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "read_secret", _boom)
        monkeypatch.setattr(mod, "write_secret", _boom)
        monkeypatch.setattr(mod, "delete_secret", _boom)
    cfg = {"anthropic": {"api_key": ks.SENTINEL},
           "smtp": {"host": "s", "username": "u", "password": ks.SENTINEL},
           "accounts": [{"imap_host": "h", "username": "u", "password": ks.SENTINEL}],
           "self_mail_secret": ks.SENTINEL,
           "secrets": {"backend": "config"}}
    # None of these may reach a raw op at the config backend.
    ks.hydrate(copy.deepcopy(cfg))
    ks.strip_for_save(copy.deepcopy(cfg))


def test_dark_ship_full_load_save_cycle_no_raw_ops(tmp_path, monkeypatch):
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "read_secret", _boom)
        monkeypatch.setattr(mod, "write_secret", _boom)
        monkeypatch.setattr(mod, "delete_secret", _boom)
    cfgfile = tmp_path / "config.json"
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    cfg = copy.deepcopy(config_io.DEFAULT_CONFIG)
    cfg["anthropic"]["api_key"] = "sk-plain"
    config_io.save_config(cfg)      # strip path
    config_io.load_config()         # hydrate path
    # engine load_config too
    monkeypatch.setattr(spam_filter, "CONFIG_PATH", cfgfile)
    spam_filter.load_config()


def test_secitem_calls_only_inside_raw_ops():
    """Static proof: every SecItem* reference in keychain_store lives inside
    read_secret / write_secret / delete_secret (or the _access ACL builder they
    call), never in hydrate / strip / backend helpers."""
    path = os.path.join(SRC, "keychain_store.py")
    with open(path) as f:
        lines = f.readlines()
    import re
    # Batch 2 adds delete_all_items() — a genuine new raw primitive that
    # enumerates by service (SecItemCopyMatching) for the delete-data uninstall
    # (§7.3). It is the only SecItem* call site added outside the original three
    # raw ops, and is reachable ONLY when the caller has already confirmed
    # backend == "keychain" (dark-ship preserved at the "config" backend).
    allowed = {"write_secret", "read_secret", "delete_secret", "_access",
               "delete_all_items"}
    current = None
    def_re = re.compile(r"^def (\w+)")
    for line in lines:
        m = def_re.match(line)
        if m:
            current = m.group(1)
        # Match real SecItem* API CALLS (name followed by "("), not the import
        # line nor the substring inside kSec* constants.
        if re.search(r"\bSecItem(Add|CopyMatching|Delete)\(", line):
            assert current in allowed, \
                f"SecItem call outside a raw op, in def {current}"


# ---------------------------------------------------------------------------
# Fail-closed preflight (§7.1) — inert at config, skips on unreadable secrets.
# ---------------------------------------------------------------------------
def test_preflight_inert_at_config_backend(tmp_path, monkeypatch):
    status = tmp_path / "keychain_status.json"
    monkeypatch.setattr(spam_filter, "KEYCHAIN_STATUS_PATH", status)
    logger = spam_filter.setup_logging("INFO")
    cfg = {"secrets": {"backend": "config"}}
    assert spam_filter._keychain_preflight(cfg, logger, "run-filter") is False
    assert not status.exists()  # no status file written at config backend


def test_preflight_skips_and_writes_status_on_errors(tmp_path, monkeypatch):
    status = tmp_path / "keychain_status.json"
    monkeypatch.setattr(spam_filter, "KEYCHAIN_STATUS_PATH", status)
    logger = spam_filter.setup_logging("INFO")
    cfg = {"secrets": {"backend": "keychain", "migration": {"state": "complete"}},
           "_secret_errors": [{"key": "anthropic-api-key", "reason": "locked"}]}
    assert spam_filter._keychain_preflight(cfg, logger, "run-filter") is True
    rec = json.loads(status.read_text())
    assert rec["ok"] is False and rec["locked"] is True
    assert rec["backend"] == "keychain"


def test_preflight_ok_writes_status_and_continues(tmp_path, monkeypatch):
    status = tmp_path / "keychain_status.json"
    monkeypatch.setattr(spam_filter, "KEYCHAIN_STATUS_PATH", status)
    logger = spam_filter.setup_logging("INFO")
    cfg = {"secrets": {"backend": "keychain", "migration": {"state": "complete"}},
           "_secret_errors": []}
    assert spam_filter._keychain_preflight(cfg, logger, "run-filter") is False
    rec = json.loads(status.read_text())
    assert rec["ok"] is True and rec["locked"] is False


def test_preflight_shadow_failure_reports_but_does_not_skip(tmp_path, monkeypatch):
    # Shadow-flagged failures (plaintext fallback worked) must NOT fail-close
    # the run — but the status file must say ok:false so tick-verify can't pass.
    status = tmp_path / "keychain_status.json"
    monkeypatch.setattr(spam_filter, "KEYCHAIN_STATUS_PATH", status)
    logger = spam_filter.setup_logging("INFO")
    cfg = {"secrets": {"backend": "keychain",
                       "migration": {"state": "items_written"}},
           "_secret_errors": [{"key": "smtp|s|u", "reason": "locked",
                               "shadow": True}]}
    assert spam_filter._keychain_preflight(cfg, logger, "run-filter") is False
    rec = json.loads(status.read_text())
    assert rec["ok"] is False
    assert rec["shadow_fallback"] is True
    assert rec["locked"] is True


def test_preflight_mixed_shadow_and_hard_still_skips(tmp_path, monkeypatch):
    # One hard failure among shadow ones must still fail the run closed.
    status = tmp_path / "keychain_status.json"
    monkeypatch.setattr(spam_filter, "KEYCHAIN_STATUS_PATH", status)
    logger = spam_filter.setup_logging("INFO")
    cfg = {"secrets": {"backend": "keychain",
                       "migration": {"state": "items_written"}},
           "_secret_errors": [
               {"key": "smtp|s|u", "reason": "missing", "shadow": True},
               {"key": "anthropic-api-key", "reason": "missing", "shadow": False},
           ]}
    assert spam_filter._keychain_preflight(cfg, logger, "run-filter") is True
    assert json.loads(status.read_text())["ok"] is False


def test_report_preflight_inert_at_config_backend(tmp_path, monkeypatch):
    status = tmp_path / "keychain_status.json"
    monkeypatch.setattr(daily_report, "KEYCHAIN_STATUS_PATH", status)
    logger = daily_report.setup_logging()
    assert daily_report._keychain_preflight({"secrets": {"backend": "config"}},
                                            logger) is False
    assert not status.exists()


# ---------------------------------------------------------------------------
# self-mail secret is backend-aware (folded into the migration, ruling #2).
# ---------------------------------------------------------------------------
def test_self_mail_secret_config_backend_unchanged(tmp_path, monkeypatch):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps({"accounts": [], "anthropic": {"api_key": ""},
                                   "secrets": {"backend": "config"}}))
    monkeypatch.setattr(utils, "_self_mail_config_path", lambda: cfgfile)
    secret = utils.get_or_create_self_mail_secret()
    assert isinstance(secret, str) and len(secret) == 64  # token_hex(32)
    # It was persisted to the plaintext config, exactly as before.
    assert json.loads(cfgfile.read_text())["self_mail_secret"] == secret


def test_self_mail_secret_keychain_backend_read_only(tmp_path, monkeypatch):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(
        {"accounts": [], "anthropic": {"api_key": ks.SENTINEL},
         "self_mail_secret": ks.SENTINEL,
         "secrets": {"backend": "keychain", "migration": {"state": "complete"}}}))
    monkeypatch.setattr(utils, "_self_mail_config_path", lambda: cfgfile)
    import keychain_store as eks
    monkeypatch.setattr(eks, "available", lambda: True)
    monkeypatch.setattr(eks, "read_secret",
                        lambda acct, keychain=None: "kc-self-mail-secret"
                        if acct == eks.self_mail_account() else None)
    # Engine path must READ from the keychain and NEVER write config back.
    before = cfgfile.read_text()
    secret = utils.get_or_create_self_mail_secret()
    assert secret == "kc-self-mail-secret"
    assert cfgfile.read_text() == before  # engine never rewrote the config

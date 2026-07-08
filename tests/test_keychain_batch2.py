#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Keychain migration — Batch 2 tests (docs/keychain-design-plan.md §11 row 2).

Scope of Batch 2: the --keychain-verify / --set-secrets-backend CLI dispatch
(§6.2 step 2, §7.2), the GUI persistence-gating helpers the wizard / Settings /
Accounts / SMTP flows use (§8, §6.3), and the uninstall item-deletion primitive
(§7.3). Plus the four Batch-1-reviewer cleanups (learner-preflight comment,
classify-eml comment, this file, and the eval-flag note in the report).

DARK-SHIP guarantee re-proved for the new surface: every helper is either a
pure decision function (no IO), a raw-op delegate, or backend-gated to a
pass-through at the "config" backend. New dark-ship proofs below assert no raw
keychain op is reachable through the GUI helpers at the "config" backend.

The real Security.framework is absent on the dev/CI machine, so
keychain_store.available() is False and the raw ops are monkeypatched with an
in-memory fake keychain exactly as the Batch-1 suite does.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_keychain_batch2.py -v
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
from mailwarden_app import app_entrypoint, config_io, paths  # noqa: E402


# ---------------------------------------------------------------------------
# In-memory fake keychain (mirrors the Batch-1 fixture).
# ---------------------------------------------------------------------------
class FakeKeychain:
    def __init__(self, items=None, locked=None, errors=None):
        self.items = dict(items or {})
        self.locked = set(locked or ())
        self.errors = set(errors or ())
        self.reads = []
        self.writes = []
        self.deletes = []

    def read(self, account_key, keychain=None):
        self.reads.append(account_key)
        if account_key in self.locked:
            raise ks.KeychainLocked(ks.errSecInteractionNotAllowed)
        if account_key in self.errors:
            raise ks.KeychainError("read", -1)
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
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "read_secret", fk.read)
        monkeypatch.setattr(mod, "write_secret", fk.write)
        monkeypatch.setattr(mod, "delete_secret", fk.delete)
        monkeypatch.setattr(mod, "available", lambda: True)
    return fk


def _kc_config(**overrides):
    """A keychain-backed, migration-complete config with one account + smtp."""
    cfg = {
        "anthropic": {"api_key": overrides.get("api_key", ks.SENTINEL)},
        "smtp": {"host": "smtp.host.com", "username": "me@host.com",
                 "password": overrides.get("smtp", ks.SENTINEL)},
        "accounts": [{"imap_host": "imap.host.com", "username": "me@host.com",
                      "password": overrides.get("imap", ks.SENTINEL)}],
        "secrets": {"backend": overrides.get("backend", "keychain"),
                    "migration": {"state": overrides.get("state", "complete")}},
    }
    return cfg


# ===========================================================================
# Pure decision helpers — safe at any backend, no IO.
# ===========================================================================
def test_expected_account_keys_present_only_and_deduped():
    cfg = {
        "anthropic": {"api_key": "sk-x"},
        "smtp": {"host": "s", "username": "u", "password": "pw"},
        "accounts": [
            {"imap_host": "h", "username": "u", "password": "p1"},
            # same mailbox -> collapses to ONE key
            {"imap_host": "H", "username": " U ", "password": "p2"},
            # empty password -> not an item
            {"imap_host": "h2", "username": "u2", "password": ""},
        ],
    }
    keys = ks.expected_account_keys(cfg)
    assert keys == [
        ks.api_key_account(),
        ks.smtp_account("s", "u"),
        ks.imap_account("h", "u"),
    ]


def test_expected_account_keys_sentinel_counts_empty_does_not():
    cfg = _kc_config(api_key=ks.SENTINEL, smtp="", imap=ks.SENTINEL)
    keys = ks.expected_account_keys(cfg)
    assert ks.api_key_account() in keys
    assert ks.imap_account("imap.host.com", "me@host.com") in keys
    # empty smtp password -> no smtp key
    assert ks.smtp_account("smtp.host.com", "me@host.com") not in keys


def test_key_in_use_shared_mailbox():
    accounts = [{"imap_host": "imap.host.com", "username": "me@host.com"}]
    assert ks.key_in_use(ks.imap_account("imap.host.com", "me@host.com"), accounts)
    assert not ks.key_in_use(ks.imap_account("other.com", "x@y.com"), accounts)
    assert not ks.key_in_use("imap|a|b", [])


def test_clear_unresolved_sentinels_blanks_only_sentinels():
    cfg = {
        "anthropic": {"api_key": "sk-REAL"},           # readable -> keep
        "smtp": {"host": "s", "username": "u", "password": ks.SENTINEL},  # unread
        "accounts": [{"imap_host": "h", "username": "u", "password": "imap-REAL"}],
        "_secret_errors": [{"key": "x", "reason": "locked"}],
    }
    blanked = ks.clear_unresolved_sentinels(cfg)
    assert cfg["anthropic"]["api_key"] == "sk-REAL"
    assert cfg["smtp"]["password"] == ""                # sentinel -> blanked
    assert cfg["accounts"][0]["password"] == "imap-REAL"
    assert blanked == [ks.smtp_account("s", "u")]
    assert "_secret_errors" not in cfg                  # underscore key dropped


# ===========================================================================
# verify_keys — reads every expected key, values never returned.
# ===========================================================================
def test_verify_keys_all_ok(fake_kc):
    cfg = _kc_config()
    fake_kc.items = {
        ks.api_key_account(): "sk",
        ks.smtp_account("smtp.host.com", "me@host.com"): "smtp",
        ks.imap_account("imap.host.com", "me@host.com"): "imap",
    }
    v = ks.verify_keys(cfg)
    assert v == {"ok": True, "missing": [], "locked": False, "errors": []}


def test_verify_keys_missing_and_locked_and_error(fake_kc):
    cfg = _kc_config()
    fake_kc.items = {}  # api key missing
    fake_kc.locked = {ks.smtp_account("smtp.host.com", "me@host.com")}
    fake_kc.errors = {ks.imap_account("imap.host.com", "me@host.com")}
    v = ks.verify_keys(cfg)
    assert v["ok"] is False
    assert v["missing"] == [ks.api_key_account()]
    assert v["locked"] is True
    assert v["errors"] == [ks.imap_account("imap.host.com", "me@host.com")]


# ===========================================================================
# GUI writers — backend-gated persistence.
# ===========================================================================
def test_sync_secret_writes_at_keychain_backend(fake_kc):
    cfg = _kc_config()
    ks.sync_secret(cfg, ks.api_key_account(),
                   ks.label_for(ks.api_key_account()), "sk-NEW")
    assert (ks.api_key_account(), "sk-NEW") in fake_kc.writes


def test_sync_secret_noop_at_config_backend(fake_kc):
    cfg = _kc_config(backend="config")
    ks.sync_secret(cfg, ks.api_key_account(),
                   ks.label_for(ks.api_key_account()), "sk-NEW")
    assert fake_kc.writes == []


def test_sync_secret_ignores_empty_and_sentinel(fake_kc):
    cfg = _kc_config()
    ks.sync_secret(cfg, ks.api_key_account(), "L", "")
    ks.sync_secret(cfg, ks.api_key_account(), "L", ks.SENTINEL)
    assert fake_kc.writes == []


def test_forget_secret_deletes_unless_shared(fake_kc):
    cfg = _kc_config()
    key = ks.imap_account("imap.host.com", "me@host.com")
    # No other account shares the key -> delete.
    ks.forget_secret(cfg, key, [])
    assert key in fake_kc.deletes
    # A remaining account shares the key -> NO delete.
    fake_kc.deletes.clear()
    ks.forget_secret(cfg, key,
                     [{"imap_host": "imap.host.com", "username": "me@host.com"}])
    assert fake_kc.deletes == []


def test_forget_secret_noop_at_config_backend(fake_kc):
    cfg = _kc_config(backend="config")
    ks.forget_secret(cfg, ks.imap_account("imap.host.com", "me@host.com"), [])
    assert fake_kc.deletes == []


def test_write_configured_secrets_writes_all_present(fake_kc):
    cfg = _kc_config(api_key="sk-real", smtp="smtp-pw", imap="imap-pw")
    ks.write_configured_secrets(cfg)
    written = dict(fake_kc.writes)
    assert written[ks.api_key_account()] == "sk-real"
    assert written[ks.smtp_account("smtp.host.com", "me@host.com")] == "smtp-pw"
    assert written[ks.imap_account("imap.host.com", "me@host.com")] == "imap-pw"


# ===========================================================================
# provision_fresh_install (§6.3) — dark at config; verify-gated at keychain.
# ===========================================================================
def test_provision_config_backend_is_noop(fake_kc):
    cfg = _kc_config(backend="config", api_key="sk-real")
    out = ks.provision_fresh_install(cfg)
    assert out == {"backend": "config", "provisioned": False}
    assert fake_kc.writes == []          # nothing touched the keychain
    assert cfg["anthropic"]["api_key"] == "sk-real"   # plaintext untouched


def test_provision_keychain_verify_ok_marks_complete(fake_kc):
    cfg = _kc_config(backend="keychain", state="none",
                     api_key="sk-real", smtp="smtp-pw", imap="imap-pw")
    out = ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": True})
    assert out == {"backend": "keychain", "provisioned": True}
    assert cfg["secrets"]["migration"]["state"] == "complete"
    assert len(fake_kc.writes) == 3      # api + smtp + imap written


def test_provision_verify_fail_falls_back_to_config(fake_kc, monkeypatch):
    deletes = {"n": 0}
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "delete_all_items",
                            lambda: deletes.__setitem__("n", deletes["n"] + 1))
    cfg = _kc_config(backend="keychain", state="none", api_key="sk-real")
    out = ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": False})
    assert out["backend"] == "config" and out["provisioned"] is False
    assert out["reason"] == "verify_failed"
    assert cfg["secrets"]["backend"] == "config"      # fell back
    assert cfg["anthropic"]["api_key"] == "sk-real"   # plaintext kept for save
    assert deletes["n"] == 1                          # partial items cleaned up


def test_provision_framework_absent_falls_back(monkeypatch):
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "available", lambda: False)
    cfg = _kc_config(backend="keychain", state="none", api_key="sk-real")
    out = ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": True})
    assert out["backend"] == "config"
    assert out["reason"] == "framework_absent"
    assert cfg["secrets"]["backend"] == "config"


# ===========================================================================
# DARK SHIP — GUI helpers reach no raw op at the config backend.
# ===========================================================================
def _boom(*a, **k):
    raise AssertionError("a raw keychain op was called at config backend")


def test_dark_ship_gui_helpers_no_raw_ops_at_config(monkeypatch):
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "read_secret", _boom)
        monkeypatch.setattr(mod, "write_secret", _boom)
        monkeypatch.setattr(mod, "delete_secret", _boom)
        monkeypatch.setattr(mod, "available", lambda: True)
    cfg = _kc_config(backend="config", api_key="sk-real", smtp="s", imap="i")
    ks.sync_secret(cfg, ks.api_key_account(), "L", "sk-new")
    ks.forget_secret(cfg, ks.imap_account("imap.host.com", "me@host.com"), [])
    ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": True})


# ===========================================================================
# CLI — --keychain-verify (§6.2 step 2).
# ===========================================================================
def test_cli_keychain_verify_framework_absent(monkeypatch, capsys):
    monkeypatch.setattr(ks, "available", lambda: False)
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 1
    assert out["ok"] is False and out["available"] is False


def test_cli_keychain_verify_ok(tmp_path, monkeypatch, capsys, fake_kc):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(_kc_config(api_key=ks.SENTINEL, smtp="",
                                             imap=ks.SENTINEL)))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    fake_kc.items = {
        ks.api_key_account(): "sk",
        ks.imap_account("imap.host.com", "me@host.com"): "imap",
    }
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and out["ok"] is True and out["available"] is True


def test_cli_keychain_verify_missing_exits_1(tmp_path, monkeypatch, capsys, fake_kc):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(_kc_config(api_key=ks.SENTINEL, smtp="",
                                             imap=ks.SENTINEL)))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    fake_kc.items = {}  # nothing in the keychain
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 1 and out["ok"] is False
    assert ks.api_key_account() in out["missing"]


# ===========================================================================
# CLI — --set-secrets-backend (§7.2 kill-switch / revert).
# ===========================================================================
def test_cli_set_backend_keychain_is_refused(capsys):
    rc = app_entrypoint._cli_set_secrets_backend("keychain")
    assert rc == 2
    assert "refusing" in capsys.readouterr().err.lower()


def test_cli_set_backend_bad_value(capsys):
    rc = app_entrypoint._cli_set_secrets_backend("banana")
    assert rc == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_cli_set_backend_config_reverts_restores_plaintext(
        tmp_path, monkeypatch, capsys, fake_kc):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(_kc_config(api_key=ks.SENTINEL,
                                             smtp=ks.SENTINEL, imap=ks.SENTINEL)))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    # Every secret is readable from the keychain.
    fake_kc.items = {
        ks.api_key_account(): "sk-REAL",
        ks.smtp_account("smtp.host.com", "me@host.com"): "SMTP-REAL",
        ks.imap_account("imap.host.com", "me@host.com"): "IMAP-REAL",
    }
    deleted = {"n": 0}
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "delete_all_items",
                            lambda: deleted.__setitem__("n", 3) or 3)
    rc = app_entrypoint._cli_set_secrets_backend("config")
    assert rc == 0
    on_disk = json.loads(cfgfile.read_text())
    # Plaintext restored, backend flipped, items deleted.
    assert on_disk["anthropic"]["api_key"] == "sk-REAL"
    assert on_disk["smtp"]["password"] == "SMTP-REAL"
    assert on_disk["accounts"][0]["password"] == "IMAP-REAL"
    assert on_disk["secrets"]["backend"] == "config"
    # BATCH-5 FLAG: revert (CLI escape hatch too) now lands on the durable
    # opt-out marker (was "none") so auto-migration never re-migrates and
    # uninstall still cleans any orphaned items.
    assert on_disk["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    assert "_secret_errors" not in on_disk       # hydrate's underscore key gone
    assert deleted["n"] == 3


def test_cli_set_backend_config_unreadable_blanks_and_warns(
        tmp_path, monkeypatch, capsys, fake_kc):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(_kc_config(api_key=ks.SENTINEL, smtp="",
                                             imap=ks.SENTINEL)))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    # API key readable; IMAP locked (unreadable) -> blanked + warned.
    fake_kc.items = {ks.api_key_account(): "sk-REAL"}
    fake_kc.locked = {ks.imap_account("imap.host.com", "me@host.com")}
    deleted_called = {"n": 0}
    for mod in (ks, engine_ks):
        monkeypatch.setattr(
            mod, "delete_all_items",
            lambda: deleted_called.__setitem__("n", deleted_called["n"] + 1) or 0)
    rc = app_entrypoint._cli_set_secrets_backend("config")
    assert rc == 0
    on_disk = json.loads(cfgfile.read_text())
    assert on_disk["anthropic"]["api_key"] == "sk-REAL"
    assert on_disk["accounts"][0]["password"] == ""   # unreadable -> blanked
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert ks.imap_account("imap.host.com", "me@host.com") in captured.err
    # D4: items KEPT because a secret was unreadable (delete would destroy the
    # last copy of an ACL-denied secret).
    assert deleted_called["n"] == 0
    assert "KEPT" in captured.out


# ===========================================================================
# Cleanup (c): GUI mint+write twin — Batch 1 left it untested.
# config_io.get_or_create_self_mail_secret under the keychain backend, item
# absent, MINTS + WRITES to the keychain + sentinelizes the config field.
# ===========================================================================
def test_gui_self_mail_secret_keychain_mint_and_write(tmp_path, monkeypatch,
                                                      fake_kc):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps({
        "accounts": [], "anthropic": {"api_key": ks.SENTINEL},
        "secrets": {"backend": "keychain", "migration": {"state": "complete"}},
    }))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    # self-mail item absent in the fake keychain -> the GUI twin must MINT it.
    secret = config_io.get_or_create_self_mail_secret()
    assert isinstance(secret, str) and len(secret) == 64      # token_hex(32)
    # It was written to the keychain under the self-mail account key…
    assert (ks.self_mail_account(), secret) in fake_kc.writes
    # …and the config field holds the SENTINEL, never the real secret on disk.
    on_disk = json.loads(cfgfile.read_text())
    assert on_disk["self_mail_secret"] == ks.SENTINEL
    assert secret not in cfgfile.read_text()


# ===========================================================================
# D1 fix — fresh-install verify is non-vacuous: expected KEYS are derived from
# the in-memory config and passed to the subprocess (not re-derived from an
# empty disk config).
# ===========================================================================
def test_spawn_keychain_verify_passes_in_memory_keys(monkeypatch, fake_kc):
    captured = {}

    class _FakeProc:
        stdout = json.dumps({"ok": True, "missing": [], "locked": False})

    def _fake_run(argv, input=None, capture_output=None, text=None, timeout=None):
        captured["argv"] = argv
        captured["input"] = input
        return _FakeProc()

    monkeypatch.setattr("subprocess.run", _fake_run)
    cfg = _kc_config(api_key="sk", smtp="", imap="pw")
    verdict = ks.spawn_keychain_verify(cfg)
    assert verdict["ok"] is True
    # The IN-MEMORY expected keys were sent (a disk re-derivation would be []).
    sent = json.loads(captured["input"])["keys"]
    assert sent == ks.expected_account_keys(cfg)
    assert ks.api_key_account() in sent
    assert ks.imap_account("imap.host.com", "me@host.com") in sent
    # Keys cross via stdin + flag, never argv (they embed usernames/hosts).
    assert "--keys-from-stdin" in captured["argv"]
    assert not any("imap|" in a for a in captured["argv"])


def test_cli_keychain_verify_uses_stdin_keys_not_empty_disk(
        tmp_path, monkeypatch, capsys, fake_kc):
    # Fresh install: config.json does NOT exist -> disk derivation is [] ->
    # WOULD pass vacuously. Passing keys on stdin must drive the verification.
    cfgfile = tmp_path / "config.json"          # deliberately not created
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    real_key = ks.imap_account("imap.host.com", "me@host.com")
    monkeypatch.setattr(sys, "argv",
                        ["mailwarden", "--keychain-verify", "--keys-from-stdin"])
    import io
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"keys": [real_key]})))
    fake_kc.items = {}                           # the passed key is MISSING
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 1                               # NOT vacuously ok
    assert out["missing"] == [real_key]          # verified the PASSED key


# ===========================================================================
# D2 fix — CLI revert no longer re-opens the Wave-6 HMAC hole. Two layers:
# (a) clear_unresolved_sentinels / _fall_back_to_config blank a sentinel
#     self-mail field; (b) both config-backend getters treat a sentinel as
#     absent and re-mint.
# ===========================================================================
def test_clear_unresolved_sentinels_blanks_self_mail():
    cfg = {"anthropic": {"api_key": "sk-real"}, "smtp": {}, "accounts": [],
           "self_mail_secret": ks.SENTINEL}
    blanked = ks.clear_unresolved_sentinels(cfg)
    assert cfg["self_mail_secret"] == ""            # blanked -> getter re-mints
    assert ks.self_mail_account() not in blanked    # not an owner re-entry item
    assert blanked == []


def test_fall_back_to_config_blanks_self_mail(monkeypatch):
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "available", lambda: False)  # skip item delete
    cfg = {"secrets": {"backend": "keychain", "migration": {"state": "none"}},
           "self_mail_secret": ks.SENTINEL, "anthropic": {"api_key": "sk"}}
    ks._fall_back_to_config(cfg)
    assert cfg["secrets"]["backend"] == "config"
    assert cfg["self_mail_secret"] == ""


def test_self_mail_getter_gui_treats_sentinel_as_absent(tmp_path, monkeypatch):
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps({
        "accounts": [], "anthropic": {"api_key": ""},
        "self_mail_secret": ks.SENTINEL,
        "secrets": {"backend": "config"}}))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    secret = config_io.get_or_create_self_mail_secret()
    assert secret != ks.SENTINEL                      # never the literal sentinel
    assert isinstance(secret, str) and len(secret) == 64
    assert json.loads(cfgfile.read_text())["self_mail_secret"] == secret


def test_self_mail_getter_engine_treats_sentinel_as_absent(tmp_path, monkeypatch):
    import utils
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps({
        "accounts": [], "anthropic": {"api_key": ""},
        "self_mail_secret": ks.SENTINEL,
        "secrets": {"backend": "config"}}))
    monkeypatch.setattr(utils, "_self_mail_config_path", lambda: cfgfile)
    secret = utils.get_or_create_self_mail_secret()
    assert secret != ks.SENTINEL
    assert isinstance(secret, str) and len(secret) == 64


def test_cli_revert_closes_self_mail_hole_end_to_end(
        tmp_path, monkeypatch, fake_kc):
    # The full attack path: keychain backend, self_mail field is the sentinel,
    # item exists. Revert to config must NOT leave the HMAC key as the public
    # sentinel constant — it blanks the field and the getter re-mints.
    cfgfile = tmp_path / "config.json"
    cfg = _kc_config(api_key=ks.SENTINEL, smtp=ks.SENTINEL, imap=ks.SENTINEL)
    cfg["self_mail_secret"] = ks.SENTINEL
    cfgfile.write_text(json.dumps(cfg))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)
    fake_kc.items = {
        ks.api_key_account(): "sk-REAL",
        ks.smtp_account("smtp.host.com", "me@host.com"): "SMTP",
        ks.imap_account("imap.host.com", "me@host.com"): "IMAP",
        ks.self_mail_account(): "kc-self-mail",
    }
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "delete_all_items", lambda: 4)
    rc = app_entrypoint._cli_set_secrets_backend("config")
    assert rc == 0
    on_disk = json.loads(cfgfile.read_text())
    assert on_disk["self_mail_secret"] != ks.SENTINEL   # blanked, not the sentinel
    # The config-backend getter now re-mints a REAL secret (never the sentinel).
    secret = config_io.get_or_create_self_mail_secret()
    assert secret != ks.SENTINEL and len(secret) == 64


# ===========================================================================
# D7 fix — provision falls back on ANY unexpected error, never propagates
# (§12.6: first-run must never be blocked).
# ===========================================================================
def test_provision_unexpected_write_error_falls_back(fake_kc, monkeypatch):
    def _boom_write(cfg):
        raise RuntimeError("objc boom")
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "write_configured_secrets", _boom_write)
        monkeypatch.setattr(mod, "delete_all_items", lambda: 0)
    cfg = _kc_config(backend="keychain", state="none", api_key="sk-real")
    out = ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": True})
    assert out["backend"] == "config" and out["provisioned"] is False
    assert out["reason"] == "write_failed"
    assert "RuntimeError" in out.get("error", "")
    assert cfg["secrets"]["backend"] == "config"


def test_provision_unexpected_verify_error_falls_back(fake_kc, monkeypatch):
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "delete_all_items", lambda: 0)

    def _boom_verify(c):
        raise RuntimeError("verify boom")
    cfg = _kc_config(backend="keychain", state="none", api_key="sk-real")
    out = ks.provision_fresh_install(cfg, verifier=_boom_verify)
    assert out["backend"] == "config" and out["reason"] == "verify_failed"
    assert cfg["secrets"]["backend"] == "config"

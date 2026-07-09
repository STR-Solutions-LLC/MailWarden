#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Keychain self-mail HMAC secret — audit finding A1-1 (MED).

The per-install self_mail_secret (Wave-6 X-MailWarden-Auth HMAC key) was left out
of the Keychain migration: expected_account_keys() omits it, so migration never
wrote it and verify never checked it, while strip_for_save() still sentinelized
the plaintext at state == "complete". Net: on a MIGRATED install the working
plaintext was destroyed, no keychain item was ever created, and the engine's
self-mail stamp went silently inert.

This suite covers the three-piece fix:
  1. the migration item-write step now provisions the self-mail item
     (keychain_migrate._ensure_self_mail_item, in _step_write);
  2. a completed-install self-repair on Dashboard open mints it if absent
     (keychain_migrate._repair_self_mail_secret, in maybe_run);
  3. the disk-derived --keychain-verify now requires it at the keychain backend
     (app_entrypoint._cli_keychain_verify).

Reuses the batch-3 harness (fake keychain + real config_io hydrate/strip path).

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_keychain_self_mail_a1_1.py -v
"""
import io
import json
import sys

import pytest

# Reuse the batch-3 harness (its module-level sys.path setup wires app/ + src/).
from test_keychain_batch3 import (  # noqa: E402
    env, _seed_config, _expected_kc_keys, _assert_migrated, REAL_SECRETS,
    ks, km, config_io, paths,
)
from mailwarden_app import app_entrypoint  # noqa: E402

_ = (env, _expected_kc_keys, REAL_SECRETS)


class _Log:
    def __init__(self):
        self.msgs = []

    def step(self, m):
        self.msgs.append(m)


def _self_mail_logged(log):
    return any("self-mail" in m for m in log.msgs)


# ===========================================================================
# Piece 1 — the migration item-write step provisions the self-mail item.
# ===========================================================================
def test_migration_preserves_existing_self_mail_plaintext_verbatim(env):
    cfg = _seed_config()
    cfg["self_mail_secret"] = "REAL-SELF-MAIL-abc123"
    env.cfgfile.write_text(json.dumps(cfg))
    result = km.run_migration(env.deps())
    assert result["action"] == "complete"
    acct = ks.self_mail_account()
    # Kept VERBATIM in the keychain (never re-minted) so in-flight HMACs verify.
    assert env.fk.items[acct] == "REAL-SELF-MAIL-abc123"
    _assert_migrated(env)
    # The plaintext is sentinelized in config.json at complete (existing strip).
    assert env.disk()["self_mail_secret"] == ks.SENTINEL
    assert "REAL-SELF-MAIL-abc123" not in env.disk_text()


def test_migration_mints_self_mail_when_config_has_none(env):
    # Default seed carries no self_mail_secret at all.
    result = km.run_migration(env.deps())
    assert result["action"] == "complete"
    val = env.fk.items[ks.self_mail_account()]
    assert len(val) == 64 and int(val, 16) >= 0     # freshly minted 32-byte hex


def test_migration_mints_self_mail_when_config_has_sentinel(env):
    cfg = _seed_config()
    cfg["self_mail_secret"] = ks.SENTINEL           # leftover from a prior revert
    env.cfgfile.write_text(json.dumps(cfg))
    km.run_migration(env.deps())
    val = env.fk.items[ks.self_mail_account()]
    # NEVER the literal public sentinel (that would re-open the spoofing bypass).
    assert val != ks.SENTINEL
    assert len(val) == 64 and int(val, 16) >= 0


def test_migration_is_idempotent_when_self_mail_item_already_exists(env):
    acct = ks.self_mail_account()
    env.fk.items[acct] = "PREEXISTING-SELF-MAIL"     # e.g. minted by first-run
    km.run_migration(env.deps())
    assert env.fk.items[acct] == "PREEXISTING-SELF-MAIL"   # untouched
    assert acct not in [w for w in env.fk.writes]          # never re-written


def test_self_mail_write_failure_surfaces_like_other_items(env, monkeypatch):
    # A write failure during self-mail provisioning must surface the SAME way any
    # other step-1 item write failure does: write_secret raises -> propagates out
    # of run_migration (maybe_run logs it non-fatal + self-heals), never a silent
    # skip. State stays "none" and plaintext is untouched (no loss).
    real_write = env.fk.write

    def boom(account_key, label, value, keychain=None):
        if account_key == ks.self_mail_account():
            raise ks.KeychainError("SecItemAdd", ks.errSecAuthFailed)
        return real_write(account_key, label, value, keychain)

    monkeypatch.setattr(ks, "write_secret", boom)
    with pytest.raises(ks.KeychainError):
        km.run_migration(env.deps())
    disk = env.disk()
    assert disk["secrets"]["migration"]["state"] == "none"     # not advanced
    assert disk["secrets"]["backend"] == "config"              # not flipped
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]  # plaintext safe


# ===========================================================================
# Piece 2 — completed-install self-repair at the Dashboard-open entry point.
# ===========================================================================
def _complete_keychain_on_disk(env, *, with_item=False):
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "keychain"
    cfg["secrets"]["migration"]["state"] = "complete"
    # A migrated install holds sentinels, not plaintext.
    cfg["anthropic"]["api_key"] = ks.SENTINEL
    cfg["smtp"]["password"] = ks.SENTINEL
    cfg["accounts"][0]["password"] = ks.SENTINEL
    env.cfgfile.write_text(json.dumps(cfg))
    env.fk.items = dict(_expected_kc_keys())
    if with_item:
        env.fk.items[ks.self_mail_account()] = "EXISTING-SELF-MAIL"


def test_repair_mints_missing_self_mail_on_dashboard_open(env):
    _complete_keychain_on_disk(env, with_item=False)
    log = _Log()
    km.maybe_run(log)
    acct = ks.self_mail_account()
    assert acct in env.fk.items                       # minted + written
    assert len(env.fk.items[acct]) == 64
    assert _self_mail_logged(log)                     # one INFO line on a mint
    # Recorded as the sentinel in config.json (getter reads the keychain item).
    assert env.disk()["self_mail_secret"] == ks.SENTINEL


def test_repair_is_noop_when_self_mail_item_present(env):
    _complete_keychain_on_disk(env, with_item=True)
    env.fk.writes.clear()
    log = _Log()
    km.maybe_run(log)
    assert env.fk.items[ks.self_mail_account()] == "EXISTING-SELF-MAIL"
    assert env.fk.writes == []                         # no write
    assert not _self_mail_logged(log)                  # no mint log


def test_repair_on_locked_keychain_does_not_crash_and_retries(env):
    _complete_keychain_on_disk(env, with_item=False)
    env.fk.locked = {ks.self_mail_account()}           # read denied
    log = _Log()
    result = km.maybe_run(log)                          # must not raise
    assert result is not None
    assert ks.self_mail_account() not in env.fk.items   # nothing minted
    assert not _self_mail_logged(log)
    # Next open with the keychain unlocked repairs it (retry).
    env.fk.locked = set()
    km.maybe_run(_Log())
    assert ks.self_mail_account() in env.fk.items


def test_repair_is_noop_at_config_backend(env):
    # Default seed is the config backend -> repair must not engage.
    before = env.disk_text()
    log = _Log()
    km.maybe_run(log)
    assert ks.self_mail_account() not in env.fk.items
    assert not _self_mail_logged(log)
    assert env.disk_text() == before


def test_repair_is_noop_when_framework_unavailable(env, monkeypatch):
    _complete_keychain_on_disk(env, with_item=False)
    monkeypatch.setattr(ks, "available", lambda: False)   # no Security.framework
    log = _Log()
    km.maybe_run(log)
    assert ks.self_mail_account() not in env.fk.items
    assert not _self_mail_logged(log)


def test_repair_is_noop_mid_migration_not_complete(env):
    # Only a COMPLETED migration self-repairs; an in-progress state is left to the
    # state machine (Piece 1 provisions it there).
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "keychain"
    cfg["secrets"]["migration"]["state"] = km.STATE_TICK_VERIFIED
    env.cfgfile.write_text(json.dumps(cfg))
    env.fk.items = dict(_expected_kc_keys())
    log = _Log()
    km._repair_self_mail_secret(config_io.load_config(), log)
    assert ks.self_mail_account() not in env.fk.items
    assert not _self_mail_logged(log)


# ===========================================================================
# Piece 3 — the disk-derived --keychain-verify checks the self-mail item.
# ===========================================================================
def _write_kc_verify_config(env, *, backend="keychain"):
    cfg = _seed_config()
    cfg["secrets"]["backend"] = backend
    cfg["secrets"]["migration"]["state"] = "complete"
    cfg["anthropic"]["api_key"] = ks.SENTINEL
    cfg["smtp"]["password"] = ks.SENTINEL
    cfg["accounts"][0]["password"] = ks.SENTINEL
    env.cfgfile.write_text(json.dumps(cfg))


def test_verify_keychain_backend_requires_self_mail_item(env, monkeypatch, capsys):
    _write_kc_verify_config(env, backend="keychain")
    env.fk.items = dict(_expected_kc_keys())           # every key EXCEPT self-mail
    monkeypatch.setattr(sys, "argv", ["mailwarden", "--keychain-verify"])
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 1 and out["ok"] is False
    assert ks.self_mail_account() in out["missing"]    # named honestly


def test_verify_keychain_backend_ok_when_self_mail_present(env, monkeypatch, capsys):
    _write_kc_verify_config(env, backend="keychain")
    env.fk.items = dict(_expected_kc_keys())
    env.fk.items[ks.self_mail_account()] = "sm-secret"
    monkeypatch.setattr(sys, "argv", ["mailwarden", "--keychain-verify"])
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and out["ok"] is True


def test_verify_config_backend_does_not_require_self_mail(env, monkeypatch, capsys):
    # At the config backend the self-mail key must NOT be added (unchanged output).
    _write_kc_verify_config(env, backend="config")
    env.fk.items = dict(_expected_kc_keys())           # no self-mail item
    monkeypatch.setattr(sys, "argv", ["mailwarden", "--keychain-verify"])
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and out["ok"] is True
    assert ks.self_mail_account() not in out["missing"]


def test_verify_stdin_keys_are_unaffected(env, monkeypatch, capsys):
    # Explicit --keys-from-stdin (fresh-install) mode passes its own keys and must
    # NOT have the self-mail key injected.
    _write_kc_verify_config(env, backend="keychain")
    only_key = ks.api_key_account()
    env.fk.items = {only_key: "sk"}                    # exactly the passed key
    monkeypatch.setattr(sys, "argv",
                        ["mailwarden", "--keychain-verify", "--keys-from-stdin"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"keys": [only_key]})))
    rc = app_entrypoint._cli_keychain_verify()
    out = json.loads(capsys.readouterr().out.strip())
    assert rc == 0 and out["ok"] is True
    assert ks.self_mail_account() not in out["missing"]

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Keychain migration — Batch 3 tests (docs/keychain-design-plan.md §11 row 3).

Scope of Batch 3: the migration state machine + shadow mode + kickstart verify +
backup scrub (§6), the kill-switch actions (§7.2), the GUI-surface decision
helpers — Dashboard banner, menu-bar warning, Settings keychain group, Help entry
(§7.1/§8) — plus carry-over A (API-key placeholder), carry-over B (uninstall
orphan cleanup), and the scope-addendum "Clear stored key" control.

THE GATE for this batch is the CRASH-STATE MATRIX (see TestCrashMatrix): a test
per state-machine step-boundary proving the next run recovers to a coherent,
filtering-capable state with NO secret loss and no half-migrated ambiguity.

Everything ships DARK behind secrets.backend. The dark-ship section re-proves no
keychain op is reachable while the backend is "config" and auto-migration is off.

These tests drive the REAL config_io.load_config / update_config (so real
hydrate-on-load + strip-on-save run) against a tmp config.json, with the raw
SecItem ops replaced by an in-memory fake keychain — exactly the Batch 1/2 idiom.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_keychain_batch3.py -v
"""
import json
import os
import sys
from datetime import datetime

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import keychain_store as engine_ks  # engine-tree copy  # noqa: E402
from mailwarden_app import keychain_store as ks  # noqa: E402
from mailwarden_app import keychain_migrate as km  # noqa: E402
from mailwarden_app import config_io, paths  # noqa: E402


# ---------------------------------------------------------------------------
# Test doubles.
# ---------------------------------------------------------------------------
class FakeKeychain:
    def __init__(self):
        self.items = {}
        self.locked = set()
        self.writes = []
        self.deletes = []

    def read(self, account_key, keychain=None):
        if account_key in self.locked:
            raise ks.KeychainLocked(ks.errSecInteractionNotAllowed)
        return self.items.get(account_key)

    def write(self, account_key, label, value, keychain=None):
        self.writes.append(account_key)
        self.items[account_key] = value

    def delete(self, account_key, missing_ok=False, keychain=None):
        self.deletes.append(account_key)
        self.items.pop(account_key, None)

    def delete_all(self):
        n = len(self.items)
        self.items.clear()
        return n


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


class FakeTick:
    """Models kickstart -> the engine writes keychain_status.json. When
    ``ok`` is True the record proves the tick (ok:true, ts newer than kickstart);
    when False the status never appears (drives the tick-timeout park)."""

    def __init__(self, clock, ok=True):
        self.clock = clock
        self.ok = ok
        self.rec = None
        self.kicks = []

    def kickstart(self, label):
        self.kicks.append(label)
        if self.ok:
            self.rec = {"ok": True, "backend": "keychain", "missing": [],
                        "locked": False, "shadow_fallback": False,
                        "ts": datetime.fromtimestamp(self.clock.now()).isoformat()}

    def read(self):
        return self.rec


REAL_SECRETS = {"api_key": "sk-REAL-KEY", "smtp": "SMTP-REAL", "imap": "IMAP-REAL"}


def _seed_config():
    return {
        "anthropic": {"api_key": REAL_SECRETS["api_key"]},
        "smtp": {"host": "smtp.host.com", "username": "me@host.com",
                 "password": REAL_SECRETS["smtp"]},
        "accounts": [{"imap_host": "imap.host.com", "username": "me@host.com",
                      "password": REAL_SECRETS["imap"], "name": "A",
                      "enabled": True}],
        "secrets": {"backend": "config",
                    "migration": {"state": "none", "verified_tick_at": "",
                                  "scrubbed_at": ""}},
    }


def _expected_kc_keys():
    return {
        ks.api_key_account(): REAL_SECRETS["api_key"],
        ks.smtp_account("smtp.host.com", "me@host.com"): REAL_SECRETS["smtp"],
        ks.imap_account("imap.host.com", "me@host.com"): REAL_SECRETS["imap"],
    }


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A migration test bed: tmp config.json seeded with plaintext secrets, a
    fake keychain wired into the real config_io hydrate/strip path, a fake
    upgrade-backup dir, a controllable clock, and a deps factory."""
    cfgfile = tmp_path / "config.json"
    cfgfile.write_text(json.dumps(_seed_config()))
    monkeypatch.setattr(paths, "CONFIG_PATH", cfgfile)

    backup_root = tmp_path / "MailWarden-upgrade-backup"
    monkeypatch.setattr(paths, "UPGRADE_BACKUP_DIR", backup_root)
    monkeypatch.setattr(km.paths, "UPGRADE_BACKUP_DIR", backup_root)

    fk = FakeKeychain()
    for mod in (ks, engine_ks):
        monkeypatch.setattr(mod, "read_secret", fk.read)
        monkeypatch.setattr(mod, "write_secret", fk.write)
        monkeypatch.setattr(mod, "delete_secret", fk.delete)
        monkeypatch.setattr(mod, "available", lambda: True)

    clock = Clock()

    class Bed:
        def __init__(self):
            self.cfgfile = cfgfile
            self.backup_root = backup_root
            self.fk = fk
            self.clock = clock

        def disk(self):
            return json.loads(self.cfgfile.read_text())

        def disk_text(self):
            return self.cfgfile.read_text()

        def make_backup(self, stamp="20260101-000000"):
            d = self.backup_root / stamp / "config"
            d.mkdir(parents=True, exist_ok=True)
            (d / "config.json").write_text(json.dumps(_seed_config()))
            return d / "config.json"

        def deps(self, *, crash_at=None, spawn_ok=True, tick_ok=True,
                 auto_enabled=True, poll_timeout=5.0, poll_interval=1.0):
            tick = FakeTick(clock, ok=tick_ok)
            self.tick = tick

            def checkpoint(label):
                if crash_at is not None and label == crash_at:
                    raise km.CrashSignal(label)

            return km.MigrationDeps(
                load_config=config_io.load_config,
                update_config=config_io.update_config,
                write_secrets=ks.write_configured_secrets,
                read_back=lambda cfg: ks.verify_keys(cfg),
                spawn_verify=lambda cfg: {"ok": bool(spawn_ok), "missing": [],
                                          "locked": False, "errors": []},
                kickstart=tick.kickstart,
                read_status=tick.read,
                scrub_backups=km.scrub_upgrade_backups,
                delete_secret=fk.delete,
                delete_all_items=fk.delete_all,
                installed=lambda: True,
                available=lambda: True,
                now=clock.now,
                sleep=clock.sleep,
                auto_enabled=auto_enabled,
                poll_timeout=poll_timeout,
                poll_interval=poll_interval,
                checkpoint=checkpoint,
            )

    return Bed()


# ===========================================================================
# Pure gate + routing helpers.
# ===========================================================================
def test_migration_should_run_dark_at_config_backend():
    cfg = _seed_config()  # backend config, state none, secrets present
    # Auto disabled (the dark default) -> never starts.
    assert km.migration_should_run(cfg, available=True, installed=True,
                                   auto_enabled=False) is False
    # Even with auto on, a dev checkout (not installed) never migrates.
    assert km.migration_should_run(cfg, available=True, installed=False,
                                   auto_enabled=True) is False
    # No framework -> never migrates.
    assert km.migration_should_run(cfg, available=False, installed=True,
                                   auto_enabled=True) is False
    # Auto on + installed + framework + secrets -> starts.
    assert km.migration_should_run(cfg, available=True, installed=True,
                                   auto_enabled=True) is True


def test_migration_should_run_no_secrets_does_not_start():
    cfg = {"anthropic": {"api_key": ""}, "smtp": {"password": ""}, "accounts": [],
           "secrets": {"backend": "config", "migration": {"state": "none"}}}
    assert km.migration_should_run(cfg, available=True, installed=True,
                                   auto_enabled=True) is False


def test_migration_should_run_resumes_in_progress_regardless_of_auto():
    for state in (km.STATE_ITEMS_WRITTEN, km.STATE_EXEC_VERIFIED,
                  km.STATE_TICK_VERIFIED, km.FAILED_EXEC_VERIFY,
                  km.FAILED_TICK_VERIFY, km.FAILED_ITEMS_WRITE):
        cfg = _seed_config()
        cfg["secrets"]["migration"]["state"] = state
        assert km.migration_should_run(cfg, available=True, installed=True,
                                       auto_enabled=False) is True, state


# BATCH-5 FLAG: "reverted_kept" -> "opted_out". Both revert branches now land on
# the unified durable opt-out marker; auto-migration must treat it as inert.
def test_migration_should_run_complete_and_opted_out_are_inert():
    for state in ("complete", ks.STATE_OPTED_OUT):
        cfg = _seed_config()
        cfg["secrets"]["migration"]["state"] = state
        assert km.migration_should_run(cfg, available=True, installed=True,
                                       auto_enabled=True) is False, state


def test_force_starts_from_none_even_when_auto_off():
    cfg = _seed_config()
    assert km.migration_should_run(cfg, available=True, installed=True,
                                   auto_enabled=False, force=True) is True


def test_action_for_routing():
    assert km._action_for(km.STATE_NONE) == "write"
    assert km._action_for(km.FAILED_ITEMS_WRITE) == "write"
    assert km._action_for(km.FAILED_EXEC_VERIFY) == "write"   # step1+2 repair
    assert km._action_for(km.STATE_ITEMS_WRITTEN) == "exec_verify"
    assert km._action_for(km.STATE_EXEC_VERIFIED) == "tick_verify"
    assert km._action_for(km.FAILED_TICK_VERIFY) == "tick_verify"
    assert km._action_for(km.STATE_TICK_VERIFIED) == "scrub"
    assert km._action_for(km.STATE_COMPLETE) is None
    # BATCH-5 FLAG: opt-out marker has no migration step (driver never advances it).
    assert km._action_for(ks.STATE_OPTED_OUT) is None


# ===========================================================================
# Happy path — none -> complete.
# ===========================================================================
def _assert_migrated(bed, expect_self_mail=True):
    """Invariants after a completed migration: state complete + scrubbed_at,
    every real secret in the keychain, config.json holds ONLY sentinels (no
    plaintext leaked)."""
    disk = bed.disk()
    assert disk["secrets"]["backend"] == "keychain"
    assert disk["secrets"]["migration"]["state"] == "complete"
    assert disk["secrets"]["migration"]["scrubbed_at"]
    # A1-1: the migration's items-write step also provisions the self-mail HMAC
    # item (minted, so its value is not asserted here). A resume that skips
    # step 1 (pre-fix mid-flight install) legitimately lacks it until the
    # maybe_run repair — those callers pass expect_self_mail=False.
    if expect_self_mail:
        assert ks.self_mail_account() in bed.fk.items
    core = {k: v for k, v in bed.fk.items.items()
            if k != ks.self_mail_account()}
    assert core == _expected_kc_keys()
    text = bed.disk_text()
    for secret in REAL_SECRETS.values():
        assert secret not in text, f"plaintext {secret!r} leaked into config.json"
    assert disk["anthropic"]["api_key"] == ks.SENTINEL
    assert disk["smtp"]["password"] == ks.SENTINEL
    assert disk["accounts"][0]["password"] == ks.SENTINEL


def test_happy_path_none_to_complete(env):
    result = km.run_migration(env.deps())
    assert result["action"] == "complete"
    _assert_migrated(env)
    # A full run through step 3 records the real-launchd tick proof timestamp.
    assert env.disk()["secrets"]["migration"]["verified_tick_at"]
    assert env.tick.kicks == [km.FILTER_LABEL]  # exactly one real launchd kick


def test_happy_path_scrubs_backups(env):
    backup_cfg = env.make_backup()
    km.run_migration(env.deps())
    scrubbed = json.loads(backup_cfg.read_text())
    for secret in REAL_SECRETS.values():
        assert secret not in backup_cfg.read_text()
    assert scrubbed["anthropic"]["api_key"] == km.SCRUB_SENTINEL
    assert scrubbed["smtp"]["password"] == km.SCRUB_SENTINEL
    assert scrubbed["accounts"][0]["password"] == km.SCRUB_SENTINEL


def test_shadow_window_keeps_plaintext_until_complete(env):
    # Stop right after the backend flip: backend keychain, but plaintext MUST
    # still be in config.json (the shadow fallback that keeps filtering alive).
    with pytest.raises(km.CrashSignal):
        km.run_migration(env.deps(crash_at="after_backend_flip"))
    disk = env.disk()
    assert disk["secrets"]["backend"] == "keychain"
    assert disk["secrets"]["migration"]["state"] == km.STATE_EXEC_VERIFIED
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]  # plaintext kept
    assert disk["accounts"][0]["password"] == REAL_SECRETS["imap"]


# ===========================================================================
# THE CRASH-STATE MATRIX (§11 row 3).
# For each step boundary: crash there, assert the on-disk state is coherent with
# NO secret loss (every secret retrievable from the keychain AND/OR still in
# plaintext), then re-enter clean and prove recovery to a complete migration.
# ===========================================================================
_CRASH_POINTS = [
    "after_write_items",
    "after_items_written",
    "after_exec_spawn",
    "after_exec_verified",
    "after_backend_flip",
    "after_kickstart",
    "after_tick_verified",
    "after_scrub",
    "after_complete",
]


@pytest.mark.parametrize("crash_at", _CRASH_POINTS)
def test_crash_matrix_recovers_with_no_secret_loss(env, crash_at):
    # 1) Crash at the boundary.
    with pytest.raises(km.CrashSignal):
        km.run_migration(env.deps(crash_at=crash_at))

    # 2) Coherence + no-secret-loss at the crash point.
    disk = env.disk()
    # config.json still parses and every secret is retrievable somewhere:
    for field_val, kc_key in (
            (disk["anthropic"]["api_key"], ks.api_key_account()),
            (disk["smtp"]["password"],
             ks.smtp_account("smtp.host.com", "me@host.com")),
            (disk["accounts"][0]["password"],
             ks.imap_account("imap.host.com", "me@host.com"))):
        has_plaintext = field_val not in ("", ks.SENTINEL) and \
            not field_val.startswith(ks.SENTINEL_PREFIX)
        in_keychain = kc_key in env.fk.items
        assert has_plaintext or in_keychain, \
            f"secret lost at {crash_at}: field={field_val!r} kc={in_keychain}"
    # Before the final scrub, plaintext MUST still be present (fallback intact).
    if crash_at != "after_complete":
        assert REAL_SECRETS["api_key"] in env.disk_text(), crash_at

    # 3) Re-enter clean: recovers to a complete, coherent migration.
    result = km.run_migration(env.deps(crash_at=None))
    assert result["action"] in ("complete", "skipped")
    _assert_migrated(env)


# ===========================================================================
# Resume from each persisted state -> complete (state × entry coverage).
# ===========================================================================
@pytest.mark.parametrize("start_state,backend", [
    (km.STATE_NONE, "config"),
    (km.STATE_NONE, "keychain"),            # D2: crashed restart/repair — resume
    (km.STATE_ITEMS_WRITTEN, "config"),
    (km.STATE_EXEC_VERIFIED, "config"),
    (km.STATE_EXEC_VERIFIED, "keychain"),   # crashed right after the flip
    (km.STATE_TICK_VERIFIED, "keychain"),
    (km.FAILED_ITEMS_WRITE, "config"),
    (km.FAILED_EXEC_VERIFY, "config"),
    (km.FAILED_TICK_VERIFY, "keychain"),
])
def test_resume_from_state_reaches_complete(env, start_state, backend):
    cfg = _seed_config()
    cfg["secrets"]["backend"] = backend
    cfg["secrets"]["migration"]["state"] = start_state
    # Pre-write items for states that imply they already exist, so a resume that
    # skips step 1 (e.g. tick_verified) still finds them.
    if start_state in (km.STATE_ITEMS_WRITTEN, km.STATE_EXEC_VERIFIED,
                       km.STATE_TICK_VERIFIED, km.FAILED_TICK_VERIFY):
        env.fk.items = dict(_expected_kc_keys())
    env.cfgfile.write_text(json.dumps(cfg))
    result = km.run_migration(env.deps())
    assert result["action"] == "complete", (start_state, backend)
    # Resumes that skip step 1 don't provision the self-mail item inside
    # run_migration — the maybe_run repair covers them (test_keychain_self_mail
    # _a1_1 proves it); every other start state must have written it.
    _assert_migrated(env, expect_self_mail=start_state not in (
        km.STATE_ITEMS_WRITTEN, km.STATE_EXEC_VERIFIED,
        km.STATE_TICK_VERIFIED, km.FAILED_TICK_VERIFY))


# ===========================================================================
# Failed-park behavior — never blocks, plaintext preserved, then self-heals.
# ===========================================================================
def test_items_write_readback_failure_parks(env, monkeypatch):
    # write "succeeds" but the read-back finds nothing -> failed:items_write.
    monkeypatch.setattr(ks, "write_configured_secrets", lambda cfg: None)
    result = km.run_migration(env.deps())
    assert result["action"] == "parked"
    assert result["state"] == km.FAILED_ITEMS_WRITE
    disk = env.disk()
    assert disk["secrets"]["backend"] == "config"       # not flipped
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]  # plaintext safe


def test_exec_verify_failure_parks_and_keeps_plaintext(env):
    result = km.run_migration(env.deps(spawn_ok=False))
    assert result["state"] == km.FAILED_EXEC_VERIFY
    disk = env.disk()
    assert disk["secrets"]["backend"] == "config"       # flip happens only in step 3
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]
    # Items were written (step 1 ran) — available for the retry. Step 1 also
    # provisions the self-mail HMAC item (A1-1); ignore it in the key comparison.
    core = {k: v for k, v in env.fk.items.items() if k != ks.self_mail_account()}
    assert core == _expected_kc_keys()
    assert ks.self_mail_account() in env.fk.items


def test_tick_verify_timeout_parks_in_shadow_mode(env):
    result = km.run_migration(env.deps(tick_ok=False))
    assert result["state"] == km.FAILED_TICK_VERIFY
    disk = env.disk()
    # Shadow mode: backend flipped BUT plaintext preserved (filtering keeps
    # working from the fallback).
    assert disk["secrets"]["backend"] == "keychain"
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]
    assert disk["accounts"][0]["password"] == REAL_SECRETS["imap"]


def test_tick_timeout_then_success_completes(env):
    km.run_migration(env.deps(tick_ok=False))       # park in shadow
    assert env.disk()["secrets"]["migration"]["state"] == km.FAILED_TICK_VERIFY
    result = km.run_migration(env.deps(tick_ok=True))  # retry succeeds
    assert result["action"] == "complete"
    _assert_migrated(env)


def test_exec_verify_failure_then_success_repairs_via_write(env):
    km.run_migration(env.deps(spawn_ok=False))      # park failed:exec_verify
    assert env.disk()["secrets"]["migration"]["state"] == km.FAILED_EXEC_VERIFY
    env.fk.writes.clear()
    result = km.run_migration(env.deps(spawn_ok=True))
    # failed:exec_verify routes back through WRITE (step1+2 repair) -> items
    # rewritten (ACL rebuilt) -> complete.
    assert result["action"] == "complete"
    assert set(env.fk.writes) == set(_expected_kc_keys())
    _assert_migrated(env)


def test_scrub_reverify_failure_drops_to_shadow_no_loss(env, monkeypatch):
    # Reach tick_verified, then make the pre-scrub re-verify fail (a transient
    # lock): the machine must NOT sentinelize the last plaintext — it parks back
    # in shadow and keeps the plaintext (ruling B3-2).
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "keychain"
    cfg["secrets"]["migration"]["state"] = km.STATE_TICK_VERIFIED
    env.cfgfile.write_text(json.dumps(cfg))
    env.fk.items = dict(_expected_kc_keys())
    env.fk.locked = set(_expected_kc_keys())        # every read now fails
    result = km.run_migration(env.deps())
    assert result["state"] == km.FAILED_TICK_VERIFY
    disk = env.disk()
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]  # plaintext kept
    for secret in REAL_SECRETS.values():
        assert secret in env.disk_text()            # nothing sentinelized/lost


def test_idempotent_complete_is_noop(env):
    km.run_migration(env.deps())
    _assert_migrated(env)
    before = env.disk_text()
    writes_before = len(env.fk.writes)
    result = km.run_migration(env.deps())
    assert result["action"] == "skipped"
    assert env.disk_text() == before                # no rewrite
    assert len(env.fk.writes) == writes_before      # no keychain op


# ===========================================================================
# DARK SHIP — nothing keychain is reachable at the config backend + auto off.
# ===========================================================================
def _boom(*a, **k):
    raise AssertionError("a keychain op ran in dark ship")


def test_auto_disabled_run_migration_touches_no_keychain_op(env):
    # BATCH-5 FLAG: auto_enabled=False is no longer the shipped default (the flip
    # turned it on), but it remains a valid global KILL SWITCH — with it off,
    # run_migration must still touch no keychain op.
    deps = env.deps(auto_enabled=False)
    # Any keychain-touching dep exploding would fail the test.
    deps.write_secrets = _boom
    deps.read_back = _boom
    deps.spawn_verify = _boom
    deps.kickstart = _boom
    deps.scrub_backups = _boom
    result = km.run_migration(deps)
    assert result == {"action": "skipped", "state": km.STATE_NONE}
    assert env.disk() == _seed_config()         # config untouched, byte-shape same


def test_auto_migrate_flag_is_on_after_the_flip():
    # BATCH-5 FLAG: this asserted False through Batches 1-4 (dark ship). Batch 5
    # (THE FLIP) turned it on; dev-safety now rests on the available()+installed()
    # gate, not on this constant (see test_maybe_run_at_config_backend_is_skipped
    # and test_flip_is_dev_safe_via_install_gate).
    assert km.AUTO_MIGRATE_ENABLED is True


def test_maybe_run_at_config_backend_is_skipped(env):
    class Log:
        def __init__(self):
            self.msgs = []

        def step(self, m):
            self.msgs.append(m)
    # build_deps() uses the real installed() (False on this dev box); even with
    # AUTO_MIGRATE_ENABLED now True (Batch 5), the available()+installed() gate
    # short-circuits to skipped, no exception, config untouched.
    out = km.maybe_run(Log())
    assert out.get("action") in ("skipped", "complete")
    assert env.disk() == _seed_config()


# ===========================================================================
# Backup scrub unit behavior.
# ===========================================================================
def test_scrub_secret_fields_covers_self_mail_and_skips_empty():
    data = {"anthropic": {"api_key": "k"}, "smtp": {"password": ""},
            "accounts": [{"password": "p"}, {"password": ""}],
            "self_mail_secret": "deadbeef"}
    assert km._scrub_secret_fields(data) is True
    assert data["anthropic"]["api_key"] == km.SCRUB_SENTINEL
    assert data["smtp"]["password"] == ""                 # empty untouched
    assert data["accounts"][0]["password"] == km.SCRUB_SENTINEL
    assert data["accounts"][1]["password"] == ""
    assert data["self_mail_secret"] == km.SCRUB_SENTINEL  # HMAC key scrubbed too


def test_scrub_is_idempotent_and_skips_bad_files(env):
    good = env.make_backup("20260101-000000")
    # A second snapshot whose config is unparseable -> skipped, never raises.
    bad_dir = env.backup_root / "20260102-000000" / "config"
    bad_dir.mkdir(parents=True, exist_ok=True)
    (bad_dir / "config.json").write_text("{not json")
    assert km.scrub_upgrade_backups() == 1                # only the good file
    assert km.scrub_upgrade_backups() == 0                # already scrubbed -> no rewrite
    assert json.loads(good.read_text())["anthropic"]["api_key"] == km.SCRUB_SENTINEL


def test_scrub_no_backup_dir_is_zero(env):
    assert km.scrub_upgrade_backups() == 0


# ===========================================================================
# Kill-switch actions (§7.2).
# ===========================================================================
def _completed_env(env):
    km.run_migration(env.deps())
    _assert_migrated(env)


def test_revert_off_keychain_restores_plaintext_and_deletes(env):
    _completed_env(env)
    out = km.revert_off_keychain(env.deps())
    assert out["unreadable"] == []
    # 3 configured secrets + the self-mail HMAC item provisioned by migration (A1-1).
    assert out["deleted"] == 4
    disk = env.disk()
    assert disk["secrets"]["backend"] == "config"
    # BATCH-5 FLAG: clean revert now lands on the durable opt-out (was "none").
    assert disk["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    assert disk["anthropic"]["api_key"] == REAL_SECRETS["api_key"]
    assert disk["smtp"]["password"] == REAL_SECRETS["smtp"]
    assert disk["accounts"][0]["password"] == REAL_SECRETS["imap"]
    assert env.fk.items == {}                              # items removed


def test_revert_off_keychain_unreadable_keeps_items_and_marks(env):
    _completed_env(env)
    # Make the IMAP item unreadable -> it can't be recovered -> KEPT + warned.
    env.fk.locked = {ks.imap_account("imap.host.com", "me@host.com")}
    out = km.revert_off_keychain(env.deps())
    assert out["deleted"] == 0                             # nothing deleted (KEPT)
    assert ks.imap_account("imap.host.com", "me@host.com") in out["unreadable"]
    disk = env.disk()
    assert disk["secrets"]["backend"] == "config"
    # BATCH-5 FLAG: KEPT revert now uses the SAME durable opt-out marker as a
    # clean revert (was "reverted_kept"); the KEPT distinction lives in
    # out["unreadable"]. keychain_items_may_exist stays True so uninstall cleans.
    assert disk["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    assert disk["accounts"][0]["password"] == ""          # unreadable -> blanked
    assert env.fk.items != {}                              # items KEPT


def test_restart_migration_repairs_from_complete(env):
    _completed_env(env)
    env.fk.writes.clear()
    result = km.restart_migration(env.deps())
    assert result["action"] == "complete"
    # From a sentinelized config, restart hydrates real values and rewrites items
    # (ACL rebuild) — every key rewritten.
    assert set(env.fk.writes) == set(_expected_kc_keys())
    _assert_migrated(env)


def test_clear_stored_api_key_deletes_item_and_blanks_field(env):
    _completed_env(env)
    out = km.clear_stored_api_key(env.deps())
    assert out["cleared"] is True
    assert ks.api_key_account() not in env.fk.items       # item deleted
    disk = env.disk()
    assert disk["anthropic"]["api_key"] == ""             # blank, NOT a sentinel
    assert not disk["anthropic"]["api_key"].startswith(ks.SENTINEL_PREFIX)
    # Other secrets untouched.
    assert ks.smtp_account("smtp.host.com", "me@host.com") in env.fk.items


def test_clear_stored_api_key_noop_at_config_backend(env):
    out = km.clear_stored_api_key(env.deps())             # backend still config
    assert out["cleared"] is False
    assert env.disk()["anthropic"]["api_key"] == REAL_SECRETS["api_key"]


# ===========================================================================
# D2 — restart_migration crash window is resumable + docstring-true.
# ===========================================================================
def test_restart_migration_repairs_and_leaves_no_stale_plaintext(env):
    _completed_env(env)
    km.restart_migration(env.deps())
    _assert_migrated(env)                     # re-sentinelized, items intact


def test_repair_crash_window_none_plus_keychain_self_heals(env):
    # Reproduce restart_migration's first act (proof 1): from a complete config,
    # persist state "none" while backend stays "keychain" (this re-materializes
    # plaintext — the shadow-window invariant). A crash HERE must self-heal.
    _completed_env(env)
    epoch = ks.revert_epoch(env.disk())
    km._set_state(env.deps(), epoch, km.STATE_NONE)   # crash simulated right after
    d = env.disk()
    assert d["secrets"]["backend"] == "keychain"
    assert d["secrets"]["migration"]["state"] == "none"
    # Plaintext re-materialized (readable keychain) => shadow fallback exists.
    assert REAL_SECRETS["api_key"] in env.disk_text()
    # D2: none+keychain is now RESUMABLE (was stranded before).
    assert km.migration_should_run(d, available=True, installed=True,
                                   auto_enabled=False) is True
    # A fresh launch drives it to completion.
    result = km.run_migration(env.deps())
    assert result["action"] == "complete"
    _assert_migrated(env)


# ===========================================================================
# D3 — a revert during a mid-flight migration is NOT silently undone.
# ===========================================================================
def test_revert_during_migration_aborts_not_resurrects(env):
    # Reproduce proof 3: drive step 1 only (state items_written), then the user
    # presses "Stop using the Keychain". The still-running migration must ABORT on
    # its next iteration (revert epoch changed) instead of rewriting items and
    # flipping the backend back to keychain.
    d = env.deps()
    start_epoch = ks.revert_epoch(d.load_config())
    cfg = d.load_config()
    km._step_write(d, cfg, start_epoch)
    assert env.disk()["secrets"]["migration"]["state"] == km.STATE_ITEMS_WRITTEN

    out = km.revert_off_keychain(d)                       # user reverts NOW
    # 3 configured secrets + the self-mail HMAC item written in step 1 (A1-1).
    assert out["deleted"] == 4
    after_revert = env.disk()
    assert after_revert["secrets"]["backend"] == "config"

    # The migration thread keeps looping from where it was (start_epoch snapshot).
    guard = 0
    result = None
    while guard < 12:
        guard += 1
        c = d.load_config()
        if ks.revert_epoch(c) != start_epoch:
            result = km._aborted(d)
            break
        action = km._action_for(ks.migration_state(c))
        if action is None:
            result = {"action": "complete"}
            break
        parked = km._STEPS[action](d, c, start_epoch)
        if parked is not None:
            result = parked
            break
    assert result["action"] == "aborted"                 # NOT complete
    final = env.disk()
    assert final["secrets"]["backend"] == "config"        # revert stands
    assert env.fk.items == {}                             # items NOT resurrected


def test_run_migration_aborts_when_revert_epoch_changes(env):
    # Full-loop version: bump the epoch out from under a fresh run at the very
    # first iteration -> clean abort, no state damage.
    cfg = _seed_config()
    cfg["secrets"]["migration"]["revert_epoch"] = 5      # run snapshots 5
    env.cfgfile.write_text(json.dumps(cfg))

    deps = env.deps()
    real_load = deps.load_config
    calls = {"n": 0}

    def bumping_load():
        c = real_load()
        calls["n"] += 1
        if calls["n"] == 2:  # after the start snapshot, before the first step
            def _bump(x):
                x["secrets"]["migration"]["revert_epoch"] = 6
            config_io.update_config(_bump)
            return real_load()
        return c
    deps.load_config = bumping_load
    result = km.run_migration(deps)
    assert result["action"] == "aborted"


# ===========================================================================
# D5 — cleared API key fails the tick CLOSED (loudly), not a silent half-run.
# ===========================================================================
def test_cleared_api_key_engine_preflight_fails_closed(env, monkeypatch):
    import spam_filter
    _completed_env(env)
    km.clear_stored_api_key(env.deps())
    # The engine tick loads + hydrates the same config the GUI just wrote.
    cfg = config_io.load_config()
    assert cfg["anthropic"]["api_key"] == ""
    assert ks.hard_secret_errors(cfg)                     # -> fail closed
    statusfile = env.backup_root.parent / "keychain_status.json"
    monkeypatch.setattr(spam_filter, "KEYCHAIN_STATUS_PATH", statusfile)
    logger = spam_filter.setup_logging("INFO")
    skip = spam_filter._keychain_preflight(cfg, logger, "run-filter")
    assert skip is True                                   # tick SKIPS (no half-run)
    rec = json.loads(statusfile.read_text())
    assert rec["ok"] is False
    assert rec["empty"] == [ks.api_key_account()]


def test_cleared_api_key_banner_says_no_api_key(env):
    _completed_env(env)
    km.clear_stored_api_key(env.deps())
    cfg = config_io.load_config()
    rec = ks.status_record(cfg, "run-filter")
    banner = km.keychain_banner(cfg, rec)
    assert banner["kind"] == "no_api_key"
    assert "API key" in banner["title"]


def test_cleared_api_key_at_config_backend_is_not_an_error(env):
    # Dark ship: an empty API key at the config backend keeps today's behavior —
    # no hard error, no skip.
    cfg = _seed_config()
    cfg["anthropic"]["api_key"] = ""                      # backend still config
    env.cfgfile.write_text(json.dumps(cfg))
    loaded = config_io.load_config()
    assert ks.hard_secret_errors(loaded) == []
    assert km.keychain_banner(loaded,
                              ks.status_record(loaded, "run-filter")) is None


# ===========================================================================
# Carry-over B — uninstall orphan gate.
# ===========================================================================
def test_keychain_items_may_exist_matrix():
    def cfg(backend, state):
        return {"secrets": {"backend": backend, "migration": {"state": state}}}
    # Dark ship (never migrated) -> False (no SecItem enumeration reachable).
    assert ks.keychain_items_may_exist(cfg("config", "none")) is False
    # Active keychain -> True.
    assert ks.keychain_items_may_exist(cfg("keychain", "complete")) is True
    # Crashed mid-migration (backend config, items written) -> True.
    assert ks.keychain_items_may_exist(cfg("config", "items_written")) is True
    # BATCH-5 FLAG: any revert (clean OR kept) -> durable opt-out -> True, so a
    # clean revert whose delete crashed still gets cleaned by delete-data
    # uninstall (was "none"->False, the §7.3 crash-window bug Part 4a fixes).
    assert ks.keychain_items_may_exist(cfg("config", ks.STATE_OPTED_OUT)) is True
    # A genuinely-never-migrated install stays "none" -> False (dark-safe).
    assert ks.keychain_items_may_exist(cfg("config", "none")) is False


def test_revert_config_to_plaintext_states():
    # BATCH-5 FLAG: both branches now set the unified durable opt-out marker
    # (was "none" / "reverted_kept"); clean vs kept lives in the returned list.
    # All readable -> opted_out (caller will delete items).
    cfg = {"anthropic": {"api_key": "sk-real"}, "smtp": {}, "accounts": [],
           "secrets": {"backend": "keychain", "migration": {"state": "complete"}}}
    assert ks.revert_config_to_plaintext(cfg) == []
    assert cfg["secrets"]["backend"] == "config"
    assert cfg["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    # Some unreadable -> opted_out + the blanked keys returned.
    cfg2 = {"anthropic": {"api_key": ks.SENTINEL},
            "smtp": {"host": "s", "username": "u", "password": "sk-real"},
            "accounts": [],
            "secrets": {"backend": "keychain", "migration": {"state": "complete"}}}
    unreadable = ks.revert_config_to_plaintext(cfg2)
    assert unreadable == [ks.api_key_account()]
    assert cfg2["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    assert cfg2["anthropic"]["api_key"] == ""


# ===========================================================================
# GUI-surface decision helpers (§7.1/§8) — pure, dark at config backend.
# ===========================================================================
def _kc_cfg(state="complete"):
    return {"secrets": {"backend": "keychain", "migration": {"state": state}}}


def test_banner_inert_at_config_backend():
    cfg = {"secrets": {"backend": "config", "migration": {"state": "none"}}}
    assert km.keychain_banner(cfg, {"ok": False, "locked": True}) is None
    assert km.keychain_warning_active(cfg, {"ok": False, "locked": True}) is False
    assert km.is_settings_group_visible(cfg) is False
    assert km.show_help_entry(cfg) is False
    assert km.api_key_placeholder_hint(cfg) == ""


def test_banner_none_when_last_run_ok():
    assert km.keychain_banner(_kc_cfg(), {"ok": True}) is None
    assert km.keychain_banner(_kc_cfg(), None) is None


def test_banner_quiet_while_migration_in_progress():
    assert km.keychain_banner(_kc_cfg("tick_verified"),
                              {"ok": False, "locked": True}) is None


def _failed_cfg(state, backend="config", plaintext=True):
    """A parked failed:* config in the REAL combination the machine produces:
    failed:items_write / failed:exec_verify park with backend STILL "config" (the
    flip is step 3), with plaintext present."""
    cfg = _seed_config()
    cfg["secrets"]["backend"] = backend
    cfg["secrets"]["migration"]["state"] = state
    if not plaintext:
        cfg["anthropic"]["api_key"] = ks.SENTINEL
        cfg["smtp"]["password"] = ks.SENTINEL
        cfg["accounts"][0]["password"] = ks.SENTINEL
    return cfg


def test_banner_migration_failed_shadow_says_working():
    # D1/D4: failed:exec_verify parks with backend "config" + plaintext present
    # (the real combination) — banner shows, and "still working" is TRUE.
    b = km.keychain_banner(_failed_cfg("failed:exec_verify"), None)
    assert b["kind"] == "migration_failed"
    assert b["action"] == "repair"
    assert "still working" in b["detail"]


def test_d1_failed_states_are_surfaced_at_config_backend():
    # D1: the two most likely post-flip failures park with backend "config"; they
    # MUST still show a banner + menu warning + Settings group (were all silent).
    for state in ("failed:items_write", "failed:exec_verify"):
        cfg = _failed_cfg(state)
        assert km.keychain_banner(cfg, None) is not None, state
        assert km.keychain_warning_active(cfg, None) is True, state
        assert km.is_settings_group_visible(cfg) is True, state


def test_d4_failed_locked_no_plaintext_names_cause_not_working():
    # D4: repair pressed with a locked keychain from a complete config -> sentinels
    # on disk (no plaintext) + status locked. Banner must name the LOCKED cause and
    # NOT claim filtering works.
    cfg = _failed_cfg("failed:items_write", backend="keychain", plaintext=False)
    b = km.keychain_banner(cfg, {"ok": False, "locked": True, "missing": [],
                                 "errors": [], "empty": []})
    assert b["kind"] == "locked"
    assert "still working" not in b["detail"]


def test_d4_failed_no_plaintext_no_status_cause_is_paused_not_working():
    cfg = _failed_cfg("failed:items_write", backend="keychain", plaintext=False)
    b = km.keychain_banner(cfg, None)
    assert b["kind"] == "migration_failed"
    assert "paused" in b["detail"] and "still working" not in b["detail"]


def test_banner_locked_missing_error_categories():
    locked = km.keychain_banner(_kc_cfg(), {"ok": False, "locked": True,
                                            "missing": [], "errors": []})
    assert locked["kind"] == "locked" and locked["action"] == "open_keychain_access"
    missing = km.keychain_banner(_kc_cfg(), {"ok": False, "locked": False,
                                             "missing": ["imap|h|u"], "errors": []})
    assert missing["kind"] == "missing" and missing["action"] == "reenter"
    err = km.keychain_banner(_kc_cfg(), {"ok": False, "locked": False,
                                         "missing": [], "errors": ["anthropic-api-key"]})
    assert err["kind"] == "error" and err["action"] == "repair"
    # Locked wins over missing when both present.
    both = km.keychain_banner(_kc_cfg(), {"ok": False, "locked": True,
                                          "missing": ["x"], "errors": []})
    assert both["kind"] == "locked"


def test_warning_active_and_group_visible_at_keychain_backend():
    cfg = _kc_cfg()
    assert km.keychain_warning_active(cfg, {"ok": False, "locked": True}) is True
    assert km.is_settings_group_visible(cfg) is True
    assert km.show_help_entry(cfg) is True


def test_api_key_placeholder_hint_reflects_whether_key_is_stored():
    # D5: the "stored in Keychain" hint must only show when a key is actually
    # stored; after a Clear (blank field) show the accurate "no key" hint.
    stored = {"anthropic": {"api_key": "sk-REAL"},
              "secrets": {"backend": "keychain", "migration": {"state": "complete"}}}
    assert km.api_key_placeholder_hint(stored) == km.API_KEY_KEYCHAIN_PLACEHOLDER
    cleared = {"anthropic": {"api_key": ""},
               "secrets": {"backend": "keychain", "migration": {"state": "complete"}}}
    assert km.api_key_placeholder_hint(cleared) == km.API_KEY_NO_KEY_HINT
    # Config backend (dark): always empty.
    assert km.api_key_placeholder_hint(
        {"anthropic": {"api_key": ""}, "secrets": {"backend": "config"}}) == ""

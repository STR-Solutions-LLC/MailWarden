# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Batch 5 (THE FLIP) tests.

Scope: the four Batch-5 parts and their crash/resume coverage.
  Part 1 — auto-migration enabled, proven dev-safe by the available()+installed()
           gate (never engages in dev/CI/source).
  Part 2 — fresh-install keychain default chosen the SAFE way (keychain only in
           the built app on a real Mac; "config" everywhere else).
  Part 3 — durable opt-out marker (both revert branches) + "Use the Keychain"
           re-enable + crash-mid-re-enable self-heal.
  Part 4 — (a) clean-revert crash-window orphans are cleanable, (b) Settings group
           description is state-accurate, (c) _has_usable_plaintext requires ALL
           configured secrets usable.

The state-machine test bed (fake keychain, controllable clock, deps factory) is
reused from test_keychain_batch3 — this file adds only Batch-5 behavior on top.
"""
import json
import os
import sys

import pytest

# Reuse the batch-3 harness (its module-level sys.path setup wires app/ + src/).
from test_keychain_batch3 import (  # noqa: E402
    env, _seed_config, _expected_kc_keys, _assert_migrated, REAL_SECRETS,
    ks, km, config_io, paths,
)

# Silence "imported but unused" for the re-exported fixture/helpers pytest needs.
_ = (env, _expected_kc_keys)


# ===========================================================================
# Part 1 — the flip + dev-safety.
# ===========================================================================
def test_auto_migrate_flag_flipped_on():
    assert km.AUTO_MIGRATE_ENABLED is True
    # build_deps() must propagate the flipped constant into the wired deps.
    assert km.build_deps().auto_enabled is True


def test_flip_is_dev_safe_via_install_gate():
    # On this dev box the Security framework is absent and /Applications has no
    # MailWarden — so even with auto enabled, nothing engages.
    deps = km.build_deps()
    assert deps.available() is False
    assert deps.installed() is False
    cfg = _seed_config()  # backend config, plaintext secrets present
    # The gate short-circuits before any keychain op regardless of auto/force.
    assert km.migration_should_run(cfg, available=False, installed=False,
                                   auto_enabled=True) is False
    assert km.migration_should_run(cfg, available=False, installed=True,
                                   auto_enabled=True, force=True) is False


def test_flip_auto_migrates_on_installed_mac(env):
    # With the REAL flipped constant plumbed through and an installed+available
    # Mac (the env fake), the auto path now drives a full migration to complete —
    # this is the behavior the flip turns on.
    result = km.run_migration(env.deps(auto_enabled=km.AUTO_MIGRATE_ENABLED))
    assert result["action"] == "complete"
    _assert_migrated(env)


# ===========================================================================
# Part 2 — fresh-install keychain default, the safe way.
# ===========================================================================
def test_fresh_install_backend_is_config_in_dev():
    # Dev/CI/source: available() False (no framework) -> config, always.
    assert km.fresh_install_backend() == "config"


def test_fresh_install_backend_keychain_only_when_available_and_installed(monkeypatch):
    monkeypatch.setattr(ks, "available", lambda: True)
    # Available but NOT installed (framework in a venv, but not the /Applications
    # app) -> still config: the keychain must engage only in the built app.
    monkeypatch.setattr(km, "_installed", lambda: False)
    assert km.fresh_install_backend() == "config"
    # Available AND installed -> keychain.
    monkeypatch.setattr(km, "_installed", lambda: True)
    assert km.fresh_install_backend() == "keychain"


def test_provision_at_config_backend_is_byte_identical_noop():
    # The dev fresh-install path: backend stays "config", provision no-ops, and
    # the config dict is unchanged (today's plaintext wizard save preserved).
    cfg = _seed_config()
    before = json.dumps(cfg, sort_keys=True)
    result = ks.provision_fresh_install(cfg)
    assert result == {"backend": "config", "provisioned": False}
    assert json.dumps(cfg, sort_keys=True) == before


def test_provision_at_keychain_backend_writes_and_completes(env):
    # Simulate the built-app fresh install: draft backend keychain, framework
    # available (env fake), verify passes -> secrets written, state complete.
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "keychain"
    result = ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": True})
    assert result == {"backend": "keychain", "provisioned": True}
    assert cfg["secrets"]["migration"]["state"] == "complete"
    assert env.fk.items == _expected_kc_keys()
    # Save now sentinelizes (strip fires at state complete) — no plaintext leaks.
    saved = ks.strip_for_save(cfg)
    assert saved["anthropic"]["api_key"] == ks.SENTINEL


def test_provision_verify_failure_falls_back_to_plaintext(env):
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "keychain"
    result = ks.provision_fresh_install(cfg, verifier=lambda c: {"ok": False})
    assert result["backend"] == "config"           # never a bricked first-run
    assert cfg["secrets"]["backend"] == "config"
    assert cfg["anthropic"]["api_key"] == REAL_SECRETS["api_key"]  # plaintext kept


# ===========================================================================
# Part 3 — durable opt-out + re-enable.
# ===========================================================================
def _opted_out_on_disk(env):
    """Put the env on a realistic post-revert state: plaintext secrets back in
    config.json, backend "config", state opted_out."""
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "config"
    cfg["secrets"]["migration"]["state"] = ks.STATE_OPTED_OUT
    env.cfgfile.write_text(json.dumps(cfg))


def test_auto_never_remigrates_opted_out(env):
    _opted_out_on_disk(env)
    before = env.disk_text()
    result = km.run_migration(env.deps())     # auto path (auto_enabled True)
    assert result["action"] == "skipped"
    assert result["state"] == ks.STATE_OPTED_OUT
    assert env.disk_text() == before          # nothing touched


def test_reenable_from_opted_out_migrates_to_complete(env):
    _opted_out_on_disk(env)
    result = km.reenable_keychain(env.deps())
    assert result["action"] == "complete"
    _assert_migrated(env)                      # backend keychain, sentinelized


def test_reenable_group_view_shows_only_the_reenable_button():
    cfg = {"secrets": {"backend": "config",
                       "migration": {"state": ks.STATE_OPTED_OUT}}}
    view = km.keychain_group_view(cfg)
    assert view["buttons"] == [km.KC_BTN_REENABLE]
    assert "settings file" in view["description"]
    assert "switch back" in view["description"].lower()
    assert km.is_settings_group_visible(cfg) is True


def test_crash_mid_reenable_self_heals(env):
    # reenable_keychain's first act (via restart_migration) persists state "none"
    # while the backend is still "config". Simulate a crash right after that.
    _opted_out_on_disk(env)
    epoch = ks.revert_epoch(env.disk())
    km._set_state(env.deps(), epoch, km.STATE_NONE)     # crash simulated here
    d = env.disk()
    assert d["secrets"]["migration"]["state"] == km.STATE_NONE
    assert d["secrets"]["backend"] == "config"
    # The opt-out is cleared; the auto path (flip on) now resumes on next launch.
    assert km.migration_should_run(d, available=True, installed=True,
                                   auto_enabled=True) is True
    result = km.run_migration(env.deps())               # next-launch auto resume
    assert result["action"] == "complete"
    _assert_migrated(env)


# Extended crash-state matrix: a re-enable crashing at EVERY step boundary must
# re-enter cleanly and reach a complete, coherent migration (no secret loss).
@pytest.mark.parametrize("crash_at", [
    "after_write_items", "after_items_written", "after_exec_spawn",
    "after_exec_verified", "after_backend_flip", "after_kickstart",
    "after_tick_verified", "after_scrub", "after_complete",
])
def test_reenable_crash_matrix_reenters_to_complete(env, crash_at):
    _opted_out_on_disk(env)
    with pytest.raises(km.CrashSignal):
        km.reenable_keychain(env.deps(crash_at=crash_at))
    # A secret is never lost: it is in config.json (plaintext/sentinel) or the kc.
    def secret_safe(field_val, kc_key):
        return (isinstance(field_val, str) and field_val != ""
                ) or kc_key in env.fk.items
    d = env.disk()
    assert secret_safe(d["anthropic"]["api_key"], ks.api_key_account())
    # Re-enter clean -> complete.
    result = km.run_migration(env.deps(crash_at=None))
    assert result["action"] in ("complete", "skipped")
    _assert_migrated(env)


# Batch-5 review MEDIUM — return coherence under a mid-re-enable revert race.
def test_reenable_revert_race_returns_truthful_aborted(env):
    # A cross-process revert (e.g. the CLI --set-secrets-backend=config escape
    # hatch) commits between restart_migration's epoch snapshot and its guarded
    # _set_state write: the reset must ABORT (opt-out preserved, zero keychain
    # writes) AND the returned action must be truthful, never "complete".
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "config"
    cfg["secrets"]["migration"] = {"state": ks.STATE_OPTED_OUT, "revert_epoch": 2}
    env.cfgfile.write_text(json.dumps(cfg))          # disk epoch = 2 (post-revert)
    deps = env.deps()
    # restart_migration snapshots a STALE epoch (1) via load_config, while the
    # real update_config inside _set_state loads the disk (epoch 2) and aborts.
    stale = json.loads(json.dumps(cfg))
    stale["secrets"]["migration"]["revert_epoch"] = 1
    deps.load_config = lambda: json.loads(json.dumps(stale))
    result = km.reenable_keychain(deps)
    assert result["action"] == "aborted"
    assert result["action"] != "complete"
    # Opt-out preserved on disk, backend unchanged, ZERO keychain writes.
    disk = env.disk()
    assert disk["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    assert disk["secrets"]["backend"] == "config"
    assert env.fk.writes == []


def test_run_migration_inert_state_is_not_reported_complete(env):
    # run_migration part-2 fix: a forced run whose state carries no migration step
    # (opted_out) must report "inert", never "complete", and touch no keychain op.
    cfg = _seed_config()
    cfg["secrets"]["backend"] = "config"
    cfg["secrets"]["migration"]["state"] = ks.STATE_OPTED_OUT
    env.cfgfile.write_text(json.dumps(cfg))
    result = km.run_migration(env.deps(), force=True)
    assert result == {"action": "inert", "state": ks.STATE_OPTED_OUT}
    assert env.fk.writes == []
    assert env.disk()["secrets"]["backend"] == "config"


# ===========================================================================
# Part 4a — clean-revert crash-window orphans stay cleanable.
# ===========================================================================
def test_clean_revert_crash_window_items_still_cleanable():
    # A clean revert recovers every secret and sets opted_out; if the caller
    # crashes BEFORE delete_all_items, the items remain — but the opt-out marker
    # keeps keychain_items_may_exist True so a later delete-data uninstall cleans
    # them (§7.3, the bug Part 4a fixes; old "none" -> False left them orphaned).
    cfg = {"anthropic": {"api_key": ks.SENTINEL}, "smtp": {}, "accounts": [],
           "secrets": {"backend": "keychain", "migration": {"state": "complete"}}}
    # (hydrated readable values would sit here; simulate all recovered)
    cfg["anthropic"]["api_key"] = "sk-real"
    unreadable = ks.revert_config_to_plaintext(cfg)
    assert unreadable == []                                  # clean revert
    assert cfg["secrets"]["migration"]["state"] == ks.STATE_OPTED_OUT
    # Caller "crashed" before deleting — items still present conceptually; the
    # gate that drives uninstall cleanup must be True.
    assert ks.keychain_items_may_exist(cfg) is True


# ===========================================================================
# Part 4b — Settings group description accuracy.
# ===========================================================================
def test_group_view_failed_at_config_describes_settings_file():
    cfg = _seed_config()
    cfg["secrets"]["migration"]["state"] = "failed:items_write"  # backend config
    view = km.keychain_group_view(cfg)
    assert "settings file" in view["description"]
    assert "login Keychain" not in view["description"]
    # Full control set still offered (behavior preserved from Batch 3).
    assert view["buttons"] == [km.KC_BTN_REPAIR, km.KC_BTN_RERUN,
                               km.KC_BTN_CLEAR, km.KC_BTN_STOP]


def test_group_view_keychain_backend_describes_keychain():
    cfg = {"secrets": {"backend": "keychain", "migration": {"state": "complete"}}}
    view = km.keychain_group_view(cfg)
    assert "login Keychain" in view["description"]
    assert view["buttons"] == [km.KC_BTN_REPAIR, km.KC_BTN_RERUN,
                               km.KC_BTN_CLEAR, km.KC_BTN_STOP]


def test_group_view_hidden_at_config_none():
    cfg = {"secrets": {"backend": "config", "migration": {"state": "none"}}}
    assert km.keychain_group_view(cfg) is None
    assert km.is_settings_group_visible(cfg) is False


# ===========================================================================
# Part 4c — _has_usable_plaintext requires ALL configured secrets usable.
# ===========================================================================
def test_usable_plaintext_all_real_is_true():
    cfg = {"anthropic": {"api_key": "sk"}, "smtp": {"password": "p"},
           "accounts": [{"password": "q"}]}
    assert km._has_usable_plaintext(cfg) is True


def test_usable_plaintext_mixed_partial_lock_is_false():
    # API key readable but an account's password is an unreadable sentinel: under
    # the all-or-nothing fail-closed rule that account's filtering is broken, so
    # "still working" must be False (Part 4c — old OR-logic wrongly said True).
    cfg = {"anthropic": {"api_key": "sk-real"}, "smtp": {"password": "smtp-real"},
           "accounts": [{"password": ks.SENTINEL}]}
    assert km._has_usable_plaintext(cfg) is False


def test_usable_plaintext_all_sentinel_is_false():
    cfg = {"anthropic": {"api_key": ks.SENTINEL}, "smtp": {"password": ks.SENTINEL},
           "accounts": [{"password": ks.SENTINEL}]}
    assert km._has_usable_plaintext(cfg) is False


def test_banner_mixed_partial_lock_is_not_still_working():
    # A failed:* park at the config backend with a mixed partial-lock must NOT
    # claim "still working" — filtering is fail-closed for the locked account.
    cfg = _seed_config()
    cfg["secrets"]["migration"]["state"] = "failed:exec_verify"  # backend config
    cfg["accounts"][0]["password"] = ks.SENTINEL                 # one unreadable
    banner = km.keychain_banner(cfg, None)
    assert banner is not None
    assert "still working" not in banner["detail"]
    assert "paused" in banner["detail"]

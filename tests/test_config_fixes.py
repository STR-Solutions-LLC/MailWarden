"""Tests for config_io migrations introduced in audit fixes C4, M16."""
import json
import os
import sys

import pytest

# Add app/ to the path so mailwarden_app is importable (matches existing test convention)
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import mailwarden_app.paths as app_paths  # noqa: E402
from mailwarden_app.config_io import DEFAULT_CONFIG, _deep_merge, load_config  # noqa: E402


# ── DEFAULT_CONFIG schema ────────────────────────────────────────────────────

def test_default_config_has_filter_confidence_threshold():
    assert DEFAULT_CONFIG["filter"]["confidence_threshold"] == 0.85

def test_default_config_anthropic_block_has_no_confidence_threshold():
    assert "confidence_threshold" not in DEFAULT_CONFIG["anthropic"]


# ── _deep_merge ──────────────────────────────────────────────────────────────

def test_deep_merge_fills_missing_top_level_key():
    base = {"a": 1, "b": 2}
    overlay = {"a": 99}
    result = _deep_merge(base, overlay)
    assert result["a"] == 99
    assert result["b"] == 2

def test_deep_merge_fills_missing_nested_key():
    base = {"filter": {"dry_run": True, "interval_minutes": 15}}
    overlay = {"filter": {"dry_run": False}}
    result = _deep_merge(base, overlay)
    assert result["filter"]["dry_run"] is False
    assert result["filter"]["interval_minutes"] == 15

def test_deep_merge_does_not_mutate_inputs():
    import copy
    base = {"a": {"x": 1}}
    overlay = {"a": {}}
    base_copy = copy.deepcopy(base)
    overlay_copy = copy.deepcopy(overlay)
    _deep_merge(base, overlay)
    assert base == base_copy
    assert overlay == overlay_copy


# ── load_config migrations ───────────────────────────────────────────────────

@pytest.fixture()
def patched_config_path(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    monkeypatch.setattr(app_paths, "CONFIG_PATH", cfg)
    return cfg


def test_load_config_migrates_anthropic_confidence_to_filter(patched_config_path):
    old = {
        "accounts": [],
        "anthropic": {
            "api_key": "sk-test",
            "model": "claude-haiku-4-5-20251001",
            "confidence_threshold": 0.70,
        },
        "filter": {"dry_run": False, "max_emails_per_run": 50, "interval_minutes": 30},
    }
    patched_config_path.write_text(json.dumps(old))
    result = load_config()
    assert result["filter"]["confidence_threshold"] == 0.70
    assert "confidence_threshold" not in result["anthropic"]


def test_load_config_does_not_overwrite_existing_filter_confidence(patched_config_path):
    cfg = {
        "accounts": [],
        "anthropic": {
            "api_key": "sk-test",
            "model": "claude-haiku-4-5-20251001",
            "confidence_threshold": 0.60,
        },
        "filter": {
            "dry_run": False,
            "max_emails_per_run": 50,
            "interval_minutes": 30,
            "confidence_threshold": 0.75,
        },
    }
    patched_config_path.write_text(json.dumps(cfg))
    result = load_config()
    assert result["filter"]["confidence_threshold"] == 0.75


def test_load_config_deep_merges_missing_keys(patched_config_path):
    minimal = {"accounts": [], "anthropic": {"api_key": "sk-test"}}
    patched_config_path.write_text(json.dumps(minimal))
    result = load_config()
    assert "signal_learner" in result
    assert "eula" in result
    assert "ui" in result
    assert result["filter"]["dry_run"] is True
    assert result["anthropic"]["api_key"] == "sk-test"


def test_load_config_does_not_overwrite_user_filter_values(patched_config_path):
    cfg = {
        "accounts": [],
        "filter": {"dry_run": False, "interval_minutes": 30, "max_emails_per_run": 50},
    }
    patched_config_path.write_text(json.dumps(cfg))
    result = load_config()
    assert result["filter"]["dry_run"] is False
    assert result["filter"]["interval_minutes"] == 30


# ── cascade config (two-model double-check) ──────────────────────────────────

def test_default_config_ships_cascade():
    """Fresh installs get the two-model cascade with the pinned stage models.
    confirm_model MUST stay claude-sonnet-4-6 (newer models 400-reject the
    temperature=0 determinism pin — regression guard)."""
    a = DEFAULT_CONFIG["anthropic"]
    assert a["classify_mode"] == "cascade"
    assert a["screen_model"] == "claude-haiku-4-5-20251001"
    assert a["confirm_model"] == "claude-sonnet-4-6"
    assert a["model"] == "claude-haiku-4-5-20251001"


def test_load_config_force_upgrades_old_installs_to_cascade(patched_config_path):
    """Pre-cascade configs (anthropic has api_key+model only) are flipped to
    cascade by the _deep_merge back-fill (Matt's force-upgrade decision,
    2026-07-02) while retaining the user's api_key and single-mode model."""
    old = {
        "accounts": [],
        "anthropic": {"api_key": "sk-test", "model": "claude-sonnet-4-6"},
    }
    patched_config_path.write_text(json.dumps(old))
    result = load_config()
    a = result["anthropic"]
    assert a["classify_mode"] == "cascade"
    assert a["screen_model"] == "claude-haiku-4-5-20251001"
    assert a["confirm_model"] == "claude-sonnet-4-6"
    # The user's previous choices are retained, not clobbered.
    assert a["api_key"] == "sk-test"
    assert a["model"] == "claude-sonnet-4-6"


def test_load_config_respects_explicit_single_mode(patched_config_path):
    """A user who later re-selects a single mode keeps it across loads —
    the back-fill only fills MISSING keys."""
    cfg = {
        "accounts": [],
        "anthropic": {"api_key": "sk-test", "classify_mode": "single",
                      "model": "claude-haiku-4-5-20251001"},
    }
    patched_config_path.write_text(json.dumps(cfg))
    result = load_config()
    assert result["anthropic"]["classify_mode"] == "single"


# ── _validate_port ───────────────────────────────────────────────────────────

from mailwarden_app.setup_assistant import _validate_port as vp  # noqa: E402


def test_validate_port_rejects_non_numeric():
    port, err = vp("abc", 993)
    assert port is None
    assert err is not None and "number" in err.lower()


def test_validate_port_rejects_zero():
    port, err = vp("0", 993)
    assert port is None
    assert err is not None and "range" in err.lower()


def test_validate_port_rejects_too_large():
    port, err = vp("65536", 993)
    assert port is None
    assert err is not None and "range" in err.lower()


def test_validate_port_accepts_valid():
    port, err = vp("993", 993)
    assert port == 993
    assert err is None


def test_validate_port_uses_default_for_empty():
    port, err = vp("", 993)
    assert port == 993
    assert err is None


def test_validate_port_accepts_boundary_values():
    p1, e1 = vp("1", 993)
    p2, e2 = vp("65535", 993)
    assert p1 == 1 and e1 is None
    assert p2 == 65535 and e2 is None


# ── B2: re-running Setup over an existing config preserves settings ───────────

from mailwarden_app.setup_assistant import _merge_finalized_config  # noqa: E402


def test_rerun_setup_preserves_existing_settings():
    """B2 regression: finalizing Setup over an existing (non-fresh) install must
    NOT wipe the user's saved settings. The merge keys off the seeded cfg
    (what config_io.load_config returns for an existing install) and the
    is_fresh_install=False flag.
    """
    # cfg as load_config() would return it for an EXISTING install: the user has
    # already accepted the EULA for an account, turned dry_run OFF, set a custom
    # interval and model, and has an account the wizard run will NOT re-add.
    existing_cfg = {
        "accounts": [
            {"username": "old@example.com", "name": "Old", "enabled": True,
             "imap_host": "imap.example.com", "imap_port": 993,
             "password": "pw", "junk_folder": "Junk",
             "folders_to_scan": ["INBOX"], "spam_action": "junk"},
        ],
        "anthropic": {"api_key": "sk-existing", "model": "claude-opus-4-custom"},
        "filter": {"dry_run": False, "max_emails_per_run": 100,
                   "interval_minutes": 42, "confidence_threshold": 0.85},
        "smtp": {"host": "smtp.example.com", "port": 587, "username": "old@example.com",
                 "password": "pw", "from_address": "old@example.com",
                 "use_starttls": True},
        "summary": {"recipient": "", "hour": 8, "minute": 0},
        "eula": {"current_version": "1.0",
                 "sent_to_accounts": {"old@example.com": "2026-01-01T00:00:00"}},
        "ui": {"menu_bar_enabled": True},
    }

    # The wizard finalize, NOT re-adding the existing account (accounts empty),
    # NOT a fresh install, with a new API key entered.
    result = _merge_finalized_config(
        cfg=existing_cfg,
        accounts=[],
        is_fresh_install=False,
        api_key="sk-new",
        recipient="",
        menu_bar_enabled=True,
    )

    # eula.sent_to_accounts preserved.
    assert result["eula"]["sent_to_accounts"] == {"old@example.com": "2026-01-01T00:00:00"}
    # filter.dry_run preserved as the EXISTING value (False) — NOT reset to True.
    assert result["filter"]["dry_run"] is False
    # interval (intervals config key) preserved.
    assert result["filter"]["interval_minutes"] == 42
    # model setting preserved.
    assert result["anthropic"]["model"] == "claude-opus-4-custom"
    # existing email account preserved (not dropped when the user doesn't re-add it).
    usernames = [a["username"] for a in result["accounts"]]
    assert "old@example.com" in usernames

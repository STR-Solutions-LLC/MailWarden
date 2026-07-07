# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Help-copy accuracy fixes (7a–7e) and dead config-key removal.

String assertions guard the corrected help wording against regression and the
old, factually-wrong phrasings against reintroduction. Also verifies the dead
DEFAULT_CONFIG keys are gone and that a legacy config still carrying them loads
without error (backward compat via _deep_merge).
"""
import json
import os
import sys

import pytest

APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import mailwarden_app.paths as app_paths  # noqa: E402
from mailwarden_app import help_content  # noqa: E402
from mailwarden_app.config_io import DEFAULT_CONFIG, load_config  # noqa: E402


# ── Item 2: help-copy accuracy ───────────────────────────────────────────────

def _all_help_text() -> str:
    """Concatenate every module-level string constant in help_content so an
    assertion can scan the whole surface regardless of which constant hosts a
    given sentence."""
    parts = []
    for name in dir(help_content):
        val = getattr(help_content, name)
        if isinstance(val, str):
            parts.append(val)
    return "\n".join(parts)


def test_7a_junked_sender_numbering_wording():
    # This sentence lives in the welcome-email body (a function, not a constant).
    body = help_content.welcome_email_body("me@example.org")
    assert "Every sender the AI or a tripwire junks is numbered" in body
    # old, false claim (blacklist-source junkings are NOT numbered) is gone
    assert "Every junked sender in that report is numbered" not in body


def test_7b_share_control_names_settings_tab():
    text = _all_help_text()
    assert "Settings tab — we will never ask for them." in text
    assert "Help tab — we will never ask for them." not in text


def test_7c_instant_match_is_poll_based():
    text = _all_help_text()
    assert "on the next inbox check, with no guessing" in text
    assert "the moment they arrive, with no guessing" not in text


def test_7d_unread_caching_opener_mentions_30_day_memory():
    text = help_content.UNREAD_CACHING_BEHAVIOR
    assert "evaluates each unread email once and then remembers it for" in text
    assert "30 days" in text
    assert "evaluates each unread email exactly once" not in text


def test_7e_github_check_is_dashboard_triggered_both_sites():
    text = _all_help_text()
    # Site 1: privacy statement outbound-connections list
    assert "when you open the Dashboard (at most once every two" in text
    # Site 2: the second privacy sentence
    assert "runs only when you open the Dashboard (at most once every two weeks)" in text
    # the old always-on phrasing must be gone from BOTH sites
    assert "GitHub, once every two weeks, to check" not in text
    assert "(once every two weeks) a GitHub version check" not in text


# ── Item 3: dead config keys removed, legacy configs still load ──────────────

def test_default_config_drops_dead_keys():
    assert "whitelist" not in DEFAULT_CONFIG
    assert "blacklist" not in DEFAULT_CONFIG
    # Wave-5-D: signal_learner is a LIVE default again — the learner reads
    # signal_learner.examples_folder (learn_signals). Only the legacy .enabled
    # sub-key stays dead/ignored.
    assert DEFAULT_CONFIG["signal_learner"] == {"examples_folder": "spam_examples"}
    assert "enabled" not in DEFAULT_CONFIG["signal_learner"]


@pytest.fixture()
def patched_config_path(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    monkeypatch.setattr(app_paths, "CONFIG_PATH", cfg)
    return cfg


def test_legacy_config_with_dead_keys_loads_without_error(patched_config_path):
    legacy = {
        "accounts": [],
        "anthropic": {"api_key": "sk-test", "model": "claude-haiku-4-5-20251001"},
        "filter": {"dry_run": False, "interval_minutes": 30,
                   "confidence_threshold": 0.85},
        # dead keys a pre-1.9 install may still carry
        "whitelist": {"folder": "/some/old/path"},
        "blacklist": {"folder": None},
        "signal_learner": {"enabled": True, "last_scan_timestamp": "2026-01-01"},
    }
    patched_config_path.write_text(json.dumps(legacy))

    result = load_config()  # must not raise

    # _deep_merge preserves user-overlay keys (ignored, never crash)
    assert result["whitelist"] == {"folder": "/some/old/path"}
    assert result["signal_learner"]["enabled"] is True
    # live keys still present/merged
    assert result["filter"]["confidence_threshold"] == 0.85
    assert result["anthropic"]["api_key"] == "sk-test"

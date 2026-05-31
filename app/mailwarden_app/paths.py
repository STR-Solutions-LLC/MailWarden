# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Single source of truth for on-disk paths used by the MailWarden app.

Keep every path the UI touches here so a rename or move requires one edit,
and so tests can monkey-patch HOME_DIR for isolation.
"""
from pathlib import Path

HOME_DIR = Path.home()
MAILWARDEN_ROOT = HOME_DIR / "MailWarden"

# Filter runtime directories
CONFIG_DIR = MAILWARDEN_ROOT / "config"
CONFIG_PATH = CONFIG_DIR / "config.json"
MEMORY_DIR = MAILWARDEN_ROOT / "memory"
LOGS_DIR = MAILWARDEN_ROOT / "logs"
SRC_DIR = MAILWARDEN_ROOT / "src"
BLACKLIST_DIR = MAILWARDEN_ROOT / "blacklist"
SPAM_EXAMPLES_DIR = MAILWARDEN_ROOT / "spam_examples"
LAUNCHD_TEMPLATES_DIR = MAILWARDEN_ROOT / "launchd"

# Individual data files
SIGNALS_PATH = MEMORY_DIR / "signals.json"
WHITELIST_PATH = MEMORY_DIR / "whitelist.json"
BLACKLIST_PATH = MEMORY_DIR / "blacklist.json"
PROCESSED_IDS_PATH = MEMORY_DIR / "processed_ids.json"
TOKEN_USAGE_PATH = MEMORY_DIR / "token_usage.json"
PENDING_SIGNALS_PATH = MEMORY_DIR / "pending_signals.json"
EULA_SENT_PATH = MEMORY_DIR / "eula_sent.json"
UPDATE_CHECK_PATH = MEMORY_DIR / "update_check.json"
INSTALLER_STATE_PATH = MEMORY_DIR / "installer_state.json"
# Last bundle version we registered SMAppService agents for. Drives the
# auto-refresh of stale registrations on upgrade — see app_entrypoint.py.
REGISTERED_VERSION_PATH = MEMORY_DIR / "registered_version.json"
# Last bundle version the one-time "MailWarden is running" welcome message was
# shown for. The Dashboard writes the current version here after showing the
# message; the menu-bar auto-open and the Dashboard message both compare against
# bootstrap.BUNDLED_FILTER_VERSION so the message appears exactly once per update.
WELCOME_SHOWN_PATH = MEMORY_DIR / "welcome_shown.json"
DECISIONS_LOG = MEMORY_DIR / "decisions.log"
# Append-only JSONL log of every AI-refinement event (proposed, approved,
# rejected, expired, withdrawn, reinforced, deleted). Consumed by the
# Dashboard's Signal History tab for the Rejected/Expired section and
# by the Active-refinement cards for "first learned / last reinforced"
# context. The canonical state of what's CURRENTLY active lives in
# signals.json["ai_refinements"]; this log is the event history.
REFINEMENTS_LOG = MEMORY_DIR / "signal_refinements.log"
FILTER_LOG = LOGS_DIR / "spam_filter.log"
FILTER_LOCK = LOGS_DIR / ".filter.lock"

# Runtime state (pidfiles, etc.). Always built from Path.home() in Python —
# NEVER from a launchd-expanded $(HOME) literal, which previously produced
# a literal "$(HOME)" path and the 1157 spawn failures.
RUN_DIR = MAILWARDEN_ROOT / "run"
DASHBOARD_PID = RUN_DIR / "dashboard.pid"
# Loopback port the running Dashboard listens on for cross-process RAISE
# requests (un-minimize + raise). Written by dashboard_ipc on startup, read
# by dashboard_instance.raise_existing(). See dashboard_ipc.py.
DASHBOARD_PORT = RUN_DIR / "dashboard.port"

# launchd destination
LAUNCH_AGENTS_DIR = HOME_DIR / "Library" / "LaunchAgents"
LAUNCHD_FILTER = LAUNCH_AGENTS_DIR / "com.mailwarden.filter.plist"
LAUNCHD_REPORT = LAUNCH_AGENTS_DIR / "com.mailwarden.report.plist"
LAUNCHD_MENUBAR = LAUNCH_AGENTS_DIR / "com.mailwarden.menubar.plist"

# Backup location for upgrades
UPGRADE_BACKUP_DIR = HOME_DIR / "MailWarden-upgrade-backup"

# Resource defaults bundled inside MailWarden.app
# Resolved by app_entrypoint.py at startup — see get_bundled_defaults_dir().


def mailwarden_installed() -> bool:
    """Return True if a valid existing install is present (config.json exists and parses)."""
    if not CONFIG_PATH.exists():
        return False
    try:
        import json
        with CONFIG_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        return isinstance(data, dict) and bool(data.get("accounts"))
    except Exception:
        return False

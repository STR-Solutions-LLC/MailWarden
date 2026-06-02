# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Self-install the MailWarden runtime directory (~/MailWarden/) from files
bundled inside MailWarden.app/Contents/Resources/.

Called from app_entrypoint.main() before dispatch. Handles three scenarios:

  A. No ~/MailWarden/src/spam_filter.py exists → fresh install.
     Copy the entire bundled payload into ~/MailWarden/.
     config/ and memory/ are populated with empty defaults so Setup Assistant
     can run normally.

  B. ~/MailWarden/ exists but installer_state.json shows an older filter_version
     than what's bundled → upgrade. Back up memory/ + config/ + spam_examples/
     to ~/MailWarden-upgrade-backup/, then refresh src/ + launchd/ + blacklist/
     + EULA.md + LICENSE + requirements.txt from the bundle. User data is
     preserved.

  C. ~/MailWarden/ exists and versions match → no-op.

In every case, this function returns quickly and never raises unless IO fails
in a way that prevents further progress.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

from . import paths

BUNDLED_FILTER_VERSION = "1.6.0-beta.13"
BUNDLED_INSTALLER_VERSION = "1.0"

# Directories/files under Contents/Resources/ that we ship as payload.
# v1.6.0: "launchd" removed — plist templates no longer live in ~/MailWarden/launchd/.
# They live inside the .app bundle at Contents/Library/LaunchAgents/ and are
# managed by SMAppService. No per-user rendering needed.
PAYLOAD_DIRS = ["src", "blacklist"]
PAYLOAD_FILES = ["EULA.md", "LICENSE", "requirements.txt"]

# Files whose content drift between bundle and installed copy is considered
# "new code present, re-deploy required" — independent of the version tag.
# Any change to these files in a ship should trigger the upgrade branch
# even when a developer forgets to bump BUNDLED_FILTER_VERSION. This fixes
# the 2026-04-19 class of bug where Matt installed a new .pkg that tagged
# itself as 1.5, saw "already at 1.5", and silently left the previous
# broken spam_filter.py in place under ~/MailWarden/src/.
DRIFT_WATCH_FILES = [
    "src/spam_filter.py",
    "src/daily_report.py",
    "src/learn_signals.py",
    "src/utils.py",
]


def _bundle_payload_root() -> Path:
    """Return the bundled payload root inside the .app, or None if unavailable."""
    here = Path(__file__).resolve()
    for ancestor in list(here.parents):
        candidate = ancestor / "payload" / "MailWarden"
        if candidate.is_dir():
            return candidate
    # Fallback for dev checkout
    dev = Path.home() / "MailWarden-installer" / "payload" / "MailWarden"
    return dev if dev.is_dir() else None


def _bundle_defaults_root() -> Path:
    here = Path(__file__).resolve()
    for ancestor in list(here.parents):
        candidate = ancestor / "defaults"
        if candidate.is_dir():
            return candidate
    dev = Path.home() / "MailWarden-installer" / "resources" / "defaults"
    return dev if dev.is_dir() else None


def _copy_dir(src: Path, dst: Path) -> None:
    """Copy src tree into dst, overwriting existing files inside dst."""
    if not src.is_dir():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def _installed_filter_version() -> str | None:
    try:
        with paths.INSTALLER_STATE_PATH.open(encoding="utf-8") as f:
            return json.load(f).get("filter_version")
    except (OSError, json.JSONDecodeError):
        return None


def _sha256_of(path: Path) -> str | None:
    import hashlib
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _code_drifted(payload_root: Path) -> bool:
    """Return True if ANY file in DRIFT_WATCH_FILES differs between the
    bundled copy and what's installed under ~/MailWarden/. This catches
    the class of bug where a developer ships new code without bumping
    BUNDLED_FILTER_VERSION — version check alone would silently leave
    the broken older code in place on the user's disk.
    """
    for rel in DRIFT_WATCH_FILES:
        bundled = payload_root / rel
        installed = paths.MAILWARDEN_ROOT / rel
        if not bundled.exists():
            continue  # bundle doesn't ship this file; nothing to compare
        if not installed.exists():
            return True  # installed side is missing entirely → refresh
        if _sha256_of(bundled) != _sha256_of(installed):
            return True
    return False


def _needs_upgrade() -> bool:
    installed = _installed_filter_version()
    if installed is None:
        return True
    if installed != BUNDLED_FILTER_VERSION:
        return True
    # Even when version tags match, check for content drift. A ship with
    # the same version tag but changed filter code must still refresh
    # ~/MailWarden/src/. Without this, a quick bugfix release would ship
    # but the user would silently keep running the old buggy code.
    bundle = _bundle_payload_root()
    if bundle is None:
        return False
    return _code_drifted(bundle)


def _backup_existing() -> Path | None:
    """Back up memory/, config/, and spam_examples/ for safety on upgrade."""
    if not paths.MAILWARDEN_ROOT.exists():
        return None
    backup_root = paths.UPGRADE_BACKUP_DIR
    backup_root.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot = backup_root / stamp
    snapshot.mkdir(parents=True, exist_ok=True)

    for sub in ("config", "memory", "spam_examples"):
        src = paths.MAILWARDEN_ROOT / sub
        if src.exists():
            shutil.copytree(src, snapshot / sub, dirs_exist_ok=True)
    return snapshot


def _write_installer_state(fresh: bool) -> None:
    state: dict = {}
    if paths.INSTALLER_STATE_PATH.exists():
        try:
            with paths.INSTALLER_STATE_PATH.open(encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError):
            state = {}
    state["installer_version"] = BUNDLED_INSTALLER_VERSION
    state["filter_version"] = BUNDLED_FILTER_VERSION
    if fresh or not state.get("installed_at"):
        state["installed_at"] = datetime.now().isoformat()
    state["last_upgrade_at"] = datetime.now().isoformat()
    paths.INSTALLER_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    import tempfile, os
    fd, tmp = tempfile.mkstemp(dir=str(paths.INSTALLER_STATE_PATH.parent), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, str(paths.INSTALLER_STATE_PATH))


# NOTE: _launchd_agents_missing_or_stale() was removed 2026-04-20 along with
# the auto-reinstall trigger in bootstrap_runtime(). The trigger fired from
# any transient state anomaly — including during a concurrent install_agents
# bootout — creating the self-perpetuating cascade that killed the menu bar
# process on every upgrade. The user can still repair stale plists via the
# Dashboard's "Restart all background services" button.


# NOTE: _launchd_plists_out_of_date() was removed in v1.6.0. It compared
# ~/Library/LaunchAgents/*.plist files against templates in ~/MailWarden/launchd/.
# v1.6.0 moved all plists inside the .app bundle (Contents/Library/LaunchAgents/)
# and switched to SMAppService for agent lifecycle. There are no per-user rendered
# plists to compare anymore. The plist templates in payload/MailWarden/launchd/
# were also deleted. Kept as a comment for historical reference only.

# NOTE: _reinstall_launchd_from_current_config() was removed 2026-04-20. Its
# only caller was the auto-reinstall trigger in bootstrap_runtime(), which
# was removed at the same time. In v1.6.0 the Dashboard's "Restart all
# background services" button calls smappservice_install.register_all() directly.


def _detect_caller_agent_label() -> str | None:
    """DEAD CODE STUB — kept for historical record and future-proofing.

    v1.6.0: SMAppService makes this unnecessary. Our code no longer calls
    launchctl bootout at all, so a process cannot SIGTERM itself by
    unloading its own label. The function is retained because:
      1. Historical record: the 2026-04-20 self-bootout cascade (v1.5.11-
         v1.5.13) was the most expensive debugging session in MailWarden's
         history. Keeping this code + comment preserves the post-mortem so
         future maintainers understand WHY the v1.5.14 guards exist.
      2. Future-proofing: if any code path ever needs to detect which
         launchd agent is running (e.g., for logging), this helper is ready.

    Original purpose: compute the correct skip_self_label for install_agents()
    so a headless agent wouldn't bootout the label of the process it was
    running in. Returns None for the Dashboard (not a launchd agent).
    """
    import sys as _sys
    argv = _sys.argv
    if "--menu-bar" in argv:
        return "com.mailwarden.menubar"
    if "--run-filter" in argv:
        return "com.mailwarden.filter"
    if "--run-report" in argv:
        return "com.mailwarden.report"
    return None


def bootstrap_runtime() -> dict:
    """Main entry: ensure ~/MailWarden/ is populated with current code.

    Returns a dict describing what happened, for logging:
        {"action": "fresh" | "upgrade" | "noop" | "refreshed" | "skip",
         "backup_path": str | None,
         "bundled_payload": str | None}
    """
    payload_root = _bundle_payload_root()
    defaults_root = _bundle_defaults_root()

    result: dict = {"action": "noop", "backup_path": None,
                     "bundled_payload": str(payload_root) if payload_root else None}

    if payload_root is None:
        # No payload available (e.g., development without bundled files). Skip
        # silently — the user is running from source.
        result["action"] = "skip"
        return result

    fresh = not paths.MAILWARDEN_ROOT.exists() or not (paths.SRC_DIR / "spam_filter.py").exists()

    if fresh:
        paths.MAILWARDEN_ROOT.mkdir(parents=True, exist_ok=True)
        for sub in PAYLOAD_DIRS:
            _copy_dir(payload_root / sub, paths.MAILWARDEN_ROOT / sub)
        for fname in PAYLOAD_FILES:
            src = payload_root / fname
            if src.exists():
                shutil.copy2(src, paths.MAILWARDEN_ROOT / fname)

        # Ensure runtime directories exist with empty structure
        paths.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        paths.MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        paths.SPAM_EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)

        # Copy empty defaults into memory/ so Setup Assistant and the filter
        # have starting files immediately.
        if defaults_root:
            for name in ("signals.json", "whitelist.json", "blacklist.json",
                         "processed_ids.json", "token_usage.json",
                         "pending_signals.json"):
                src = defaults_root / name
                dst = paths.MEMORY_DIR / name
                if src.exists() and not dst.exists():
                    shutil.copy2(src, dst)

        _write_installer_state(fresh=True)
        result["action"] = "fresh"
        return result

    if _needs_upgrade():
        backup = _backup_existing()
        if backup:
            result["backup_path"] = str(backup)

        # Replace code directories with bundled versions
        for sub in PAYLOAD_DIRS:
            src = payload_root / sub
            if src.exists():
                dst = paths.MAILWARDEN_ROOT / sub
                # For src/ and launchd/, replace wholesale. For blacklist/,
                # merge (keep user customizations of skip_names.txt if any).
                if sub == "blacklist":
                    _copy_dir(src, dst)  # overwrites skip_names.txt with new version
                else:
                    if dst.exists():
                        shutil.rmtree(dst)
                    _copy_dir(src, dst)

        for fname in PAYLOAD_FILES:
            src = payload_root / fname
            if src.exists():
                shutil.copy2(src, paths.MAILWARDEN_ROOT / fname)

        # v1.6.0: bootstrap no longer calls launchctl or install_agents.
        # Agent lifecycle is managed by SMAppService (smappservice_install.py).
        # After bootstrap completes, app_entrypoint.py calls
        # smappservice_install.register_all_if_needed() — Dashboard-only.
        # The former launchd_install.install_agents() call that lived here
        # was the upgrade-branch call removed in v1.6.0; its only job was to
        # re-render and reload the ~/Library/LaunchAgents/ plists. With
        # SMAppService, plists live inside the .app bundle and Apple manages
        # their lifecycle — no per-user rendering, no launchctl needed.
        #
        # Defense-in-depth note: _detect_caller_agent_label() and the v1.5.14
        # skip_self_label guards in launchd_install.py are kept as dead-code
        # stubs (see below) because the underlying pattern — "never bootout
        # yourself from inside a launchd process" — is still architecturally
        # correct even though SMAppService makes the scenario structurally
        # impossible.

        _write_installer_state(fresh=False)
        result["action"] = "upgrade"
        return result

    # Fix 5 (2026-04-20): the former auto-reinstall trigger here
    # (if _launchd_agents_missing_or_stale(): _reinstall_launchd_from_current_config())
    # was removed. The trigger fired from any transient state anomaly —
    # including during a concurrent install_agents bootout from another
    # process — producing a self-perpetuating cascade that SIGTERMed the
    # menu bar on every upgrade. The Dashboard's "Restart all background
    # services" button is the supported way to repair stale plists.
    return result

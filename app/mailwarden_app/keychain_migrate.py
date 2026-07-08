# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Keychain migration state machine + backup scrub + GUI surface decisions.

Design plan: docs/keychain-design-plan.md §6 (migration state machine, shadow
mode, kickstart verify, backup scrub), §7 (runtime failure surfacing, kill
switch), §8 (UI). This is the Batch-3 orchestrator.

Dashboard-process ONLY. The engine (payload/MailWarden/src) never migrates and
never imports this module — the migration writer is the one process allowed to
create keychain items (§5.2), and the only one with UI to surface a failure. So,
unlike keychain_store.py, this file is NOT duplicated into the engine tree.

DARK SHIP. Everything here is inert while the shipped default backend "config"
is in force:

  * ``AUTO_MIGRATE_ENABLED`` is False, so run_migration() never INITIATES a
    migration (state "none" + backend "config" -> no-op). No config-backend beta
    ever holds an in-progress state, so the resume path is unreachable too — the
    whole state machine is provably inert (proved by the dark-ship tests).
  * Every GUI-surface helper (keychain_banner, keychain_warning_active,
    api_key_placeholder_hint, help gating) returns "nothing to show" at the
    config backend.

The migration itself is crash-safe and idempotent: state lives in
``secrets.migration.state`` (persisted through the locked config_io.update_config),
each step re-does its work harmlessly on re-entry, and plaintext survives in
config.json until step 4's scrub — so a crash between any two steps recovers to a
coherent, filtering-capable state with no secret loss (the crash-state matrix
gate, §11 row 3).
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

from . import config_io
from . import keychain_store
from . import paths


# ---------------------------------------------------------------------------
# States (§6.2).  none -> items_written -> exec_verified -> tick_verified ->
# complete.  Any step may instead park at failed:<reason> (never blocks the app;
# self-heals on the next Dashboard launch).
# ---------------------------------------------------------------------------
STATE_NONE = "none"
STATE_ITEMS_WRITTEN = "items_written"
STATE_EXEC_VERIFIED = "exec_verified"
STATE_TICK_VERIFIED = "tick_verified"
STATE_COMPLETE = "complete"

FAILED_ITEMS_WRITE = "failed:items_write"
FAILED_EXEC_VERIFY = "failed:exec_verify"
FAILED_TICK_VERIFY = "failed:tick_verify"

# States from which the driver resumes work on re-entry (self-heal). A pure
# config-backend beta never holds any of these (nothing starts a migration), so
# they are reachable only after Batch 5 lights the feature.
_RESUMABLE = frozenset({
    STATE_ITEMS_WRITTEN, STATE_EXEC_VERIFIED, STATE_TICK_VERIFIED,
    FAILED_ITEMS_WRITE, FAILED_EXEC_VERIFY, FAILED_TICK_VERIFY,
})

# DARK-SHIP MASTER SWITCH (§11). False until Batch 5's M1 checklist passes; then
# the auto-migration trigger turns on. While False, run_migration() never starts
# a migration at the config backend. (Recorded ruling B3-1.)
AUTO_MIGRATE_ENABLED = False

# The value each backup-config secret field is overwritten with (§6.4). It starts
# with keychain_store.SENTINEL_PREFIX so a restored scrubbed backup is treated as
# "absent — re-enter" by every sentinel-aware reader, never served as a live
# secret (same guard clear_unresolved_sentinels / the config-backend getters use).
SCRUB_SENTINEL = "@keychain:scrubbed"

FILTER_LABEL = "com.mailwarden.filter"

# Poll budget for the real-launchd tick proof (§6.2 step 3): kickstart the filter
# agent, then poll keychain_status.json for an ok:true record newer than the
# kickstart, up to ~90s.
DEFAULT_POLL_TIMEOUT = 90.0
DEFAULT_POLL_INTERVAL = 3.0


class CrashSignal(Exception):
    """TEST-ONLY. Raised by an injected checkpoint to simulate a process crash
    between two migration steps, driving the crash-state matrix. Production
    checkpoints are no-ops, so this never fires in the shipped app."""

    def __init__(self, label: str):
        self.label = label
        super().__init__(f"simulated crash at checkpoint {label!r}")


def _noop_checkpoint(label: str) -> None:
    return None


def _noop_log(msg: str) -> None:
    return None


@dataclass
class MigrationDeps:
    """Injection seam for the state machine so the crash matrix (§11 row 3) can
    drive it headlessly. build_deps() wires the real callables; tests substitute
    fakes. Every side-effecting operation the driver performs goes through one of
    these, so a test can crash at any boundary and re-enter deterministically."""

    load_config: Callable[[], dict]
    update_config: Callable[[Callable[[dict], None]], dict]
    write_secrets: Callable[[dict], None]           # keychain_store.write_configured_secrets
    read_back: Callable[[dict], dict]               # keychain_store.verify_keys (in-process)
    spawn_verify: Callable[[dict], dict]            # keychain_store.spawn_keychain_verify
    kickstart: Callable[[str], None]                # launchctl kickstart the filter agent
    read_status: Callable[[], Optional[dict]]       # parse keychain_status.json
    scrub_backups: Callable[[], int]                # scrub_upgrade_backups
    delete_secret: Callable[..., None]              # keychain_store.delete_secret
    delete_all_items: Callable[[], int]             # keychain_store.delete_all_items
    installed: Callable[[], bool]                   # both trusted /Applications paths exist
    available: Callable[[], bool]                   # keychain_store.available
    now: Callable[[], float]                        # monotonic-ish wall clock (seconds)
    sleep: Callable[[float], None]
    auto_enabled: bool = AUTO_MIGRATE_ENABLED
    poll_timeout: float = DEFAULT_POLL_TIMEOUT
    poll_interval: float = DEFAULT_POLL_INTERVAL
    checkpoint: Callable[[str], None] = _noop_checkpoint
    log: Callable[[str], None] = _noop_log


# ---------------------------------------------------------------------------
# Gate + state routing.
# ---------------------------------------------------------------------------

def _has_migratable_secrets(config: dict) -> bool:
    return bool(keychain_store.expected_account_keys(config))


def migration_should_run(config: dict, *, available: bool, installed: bool,
                         auto_enabled: bool, force: bool = False) -> bool:
    """Decide whether the driver does anything for ``config`` right now.

    - Requires the Security framework AND both trusted /Applications executables
      (a dev checkout / source run never migrates).
    - "complete" -> nothing to do.
    - A resumable in-progress/failed state -> always resume (self-heal), or when
      ``force`` (the manual "Re-run Keychain setup" button) even from "none".
    - "none" + backend "config" -> START only when auto-migration is enabled
      (Batch 5) or ``force``, and there is at least one secret to migrate.
    - Any other/unknown state (e.g. "reverted_kept") -> inert.

    DARK: with auto_enabled False and no in-progress state (the only reality in a
    config-backend beta), this returns False before any keychain op is reached."""
    if not (available and installed):
        return False
    state = keychain_store.migration_state(config)
    if state == STATE_COMPLETE:
        return False
    if force and state != STATE_COMPLETE:
        return _has_migratable_secrets(config) or state in _RESUMABLE
    if state in _RESUMABLE:
        return True
    if state == STATE_NONE and keychain_store.backend_of(config) == "keychain":
        # D2: a crash inside restart_migration/repair — whose first act persists
        # state "none" while the backend is still "keychain" (and re-materializes
        # the plaintext fallback) — must self-heal on the next launch. Dark-safe:
        # a config-backend beta never holds backend "keychain".
        return True
    if state == STATE_NONE and keychain_store.backend_of(config) == "config":
        return bool(auto_enabled) and _has_migratable_secrets(config)
    return False


def _action_for(state: str) -> Optional[str]:
    """Map a persisted state to the step to run next. A failed:exec_verify redoes
    the WRITE (delete+add rebuilds the ACL — the universal repair, §7.1: "re-runs
    step 1+2"); failed:tick_verify just retries the kickstart (§6.2)."""
    if state in (STATE_NONE, FAILED_ITEMS_WRITE, FAILED_EXEC_VERIFY):
        return "write"
    if state == STATE_ITEMS_WRITTEN:
        return "exec_verify"
    if state in (STATE_EXEC_VERIFIED, FAILED_TICK_VERIFY):
        return "tick_verify"
    if state == STATE_TICK_VERIFIED:
        return "scrub"
    return None  # complete / unknown


# ---------------------------------------------------------------------------
# Persisting state transitions (each a locked update_config touching ONLY the
# migration keys, exactly like the rest of the app's config writers).
# ---------------------------------------------------------------------------

def _guarded_update(deps: MigrationDeps, epoch: int,
                    apply: Callable[[dict], None]) -> bool:
    """Apply ``apply(cfg)`` through the locked update_config, but ONLY if the
    revert epoch still matches ``epoch``. Returns True when it was ABORTED — a
    concurrent revert bumped the epoch — in which case NOTHING is written and the
    revert's terminal state stands (defect D3). Because update_config loads fresh
    inside the lock, the check sees any revert that already committed."""
    box = {"aborted": False}

    def _m(cfg: dict) -> None:
        if keychain_store.revert_epoch(cfg) != epoch:
            box["aborted"] = True
            return
        apply(cfg)

    deps.update_config(_m)
    return box["aborted"]


def _set_state(deps: MigrationDeps, epoch: int, state: str) -> bool:
    def _apply(cfg: dict) -> None:
        cfg.setdefault("secrets", {}).setdefault("migration", {})["state"] = state
    return _guarded_update(deps, epoch, _apply)


def _set_backend_keychain(deps: MigrationDeps, epoch: int) -> bool:
    """Step 3a (§6.2): flip the backend to "keychain" while state stays
    exec_verified. Plaintext SURVIVES in config.json (strip_for_save preserves it
    until state == "complete") — this opens the shadow-mode window."""
    def _apply(cfg: dict) -> None:
        cfg.setdefault("secrets", {})["backend"] = "keychain"
    return _guarded_update(deps, epoch, _apply)


def _set_tick_verified(deps: MigrationDeps, epoch: int) -> bool:
    def _apply(cfg: dict) -> None:
        mig = cfg.setdefault("secrets", {}).setdefault("migration", {})
        mig["state"] = STATE_TICK_VERIFIED
        mig["verified_tick_at"] = datetime.now().isoformat()
    return _guarded_update(deps, epoch, _apply)


def _set_complete(deps: MigrationDeps, epoch: int) -> bool:
    """Step 4b (§6.2): state -> complete + scrubbed_at, in one locked update whose
    save sentinelizes the main config (strip_for_save fires at "complete"), so the
    plaintext-in-config removal and the state flip land in one atomic write."""
    def _apply(cfg: dict) -> None:
        mig = cfg.setdefault("secrets", {}).setdefault("migration", {})
        mig["state"] = STATE_COMPLETE
        mig["scrubbed_at"] = datetime.now().isoformat()
    return _guarded_update(deps, epoch, _apply)


def _parked(state: str, detail: Any) -> dict:
    return {"action": "parked", "state": state, "detail": detail}


def _aborted(deps: MigrationDeps) -> dict:
    return {"action": "aborted", "reason": "revert",
            "state": keychain_store.migration_state(deps.load_config())}


# ---------------------------------------------------------------------------
# The four steps (§6.2). Each returns None to let the driver continue, or a
# parked dict to stop this run at a failed:* state (never blocks the app).
# ---------------------------------------------------------------------------

def _step_write(deps: MigrationDeps, cfg: dict, epoch: int) -> Optional[dict]:
    # Step 1: write every currently-plaintext configured secret, then read each
    # back IN-PROCESS to confirm the write. Plaintext stays untouched (backend is
    # still "config" here). Re-running re-upserts — safe.
    deps.write_secrets(cfg)
    deps.checkpoint("after_write_items")
    verdict = deps.read_back(cfg)
    if not verdict.get("ok"):
        if _set_state(deps, epoch, FAILED_ITEMS_WRITE):
            return _aborted(deps)
        return _parked(FAILED_ITEMS_WRITE, verdict)
    if _set_state(deps, epoch, STATE_ITEMS_WRITTEN):
        return _aborted(deps)
    deps.checkpoint("after_items_written")
    return None


def _step_exec_verify(deps: MigrationDeps, cfg: dict, epoch: int) -> Optional[dict]:
    # Step 2: spawn the OTHER code identity (the bundled python) to read every
    # item headlessly — the faithful test of the ACL/DR path the launchd agents
    # use (keychain trust is evaluated against the main executable, not the
    # script). Plaintext still intact; a failure parks with the app fully working
    # on the config backend.
    verdict = deps.spawn_verify(cfg)
    deps.checkpoint("after_exec_spawn")
    if not verdict.get("ok"):
        if _set_state(deps, epoch, FAILED_EXEC_VERIFY):
            return _aborted(deps)
        return _parked(FAILED_EXEC_VERIFY, verdict)
    if _set_state(deps, epoch, STATE_EXEC_VERIFIED):
        return _aborted(deps)
    deps.checkpoint("after_exec_verified")
    return None


def _status_proves_tick(rec: Optional[dict], baseline: float) -> bool:
    """A keychain_status.json record proves the tick iff every keychain read
    genuinely succeeded (ok:true — a shadow plaintext fallback reports ok:false,
    Batch 1) AND it was written AFTER the kickstart."""
    if not isinstance(rec, dict) or not rec.get("ok"):
        return False
    ts = rec.get("ts")
    if not isinstance(ts, str) or not ts:
        return False
    try:
        rec_epoch = datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return False
    return rec_epoch >= baseline


def _step_tick_verify(deps: MigrationDeps, cfg: dict, epoch: int) -> Optional[dict]:
    # Step 3: open the shadow window (flip backend -> keychain; plaintext stays as
    # the fallback), kickstart a REAL launchd filter run, and poll the engine's
    # status file for an ok:true record newer than the kickstart. A timeout parks
    # in shadow mode — filtering keeps working from the plaintext fallback.
    if _set_backend_keychain(deps, epoch):
        return _aborted(deps)
    deps.checkpoint("after_backend_flip")
    baseline = deps.now()
    deps.kickstart(FILTER_LABEL)
    deps.checkpoint("after_kickstart")
    deadline = baseline + deps.poll_timeout
    proven = False
    while deps.now() < deadline:
        if _status_proves_tick(deps.read_status(), baseline):
            proven = True
            break
        deps.sleep(deps.poll_interval)
    if not proven:
        if _set_state(deps, epoch, FAILED_TICK_VERIFY):
            return _aborted(deps)
        return _parked(FAILED_TICK_VERIFY, {"reason": "tick_timeout"})
    if _set_tick_verified(deps, epoch):
        return _aborted(deps)
    deps.checkpoint("after_tick_verified")
    return None


def _step_scrub(deps: MigrationDeps, cfg: dict, epoch: int) -> Optional[dict]:
    # Step 4: destroy plaintext. A DEFENSIVE in-process re-verify first — the
    # keychain proved good at tick-verify, but never sentinelize the last
    # plaintext copy if a read is failing right now; a failure drops back to
    # shadow (failed:tick_verify) and retries later (safe direction, ruling
    # B3-2). Then scrub backups FIRST (idempotent, while plaintext still present),
    # then state -> complete which sentinelizes the main config in one write.
    verdict = deps.read_back(cfg)
    if not verdict.get("ok"):
        if _set_state(deps, epoch, FAILED_TICK_VERIFY):
            return _aborted(deps)
        return _parked(FAILED_TICK_VERIFY, {"reason": "reverify_failed",
                                            "verdict": verdict})
    deps.scrub_backups()
    deps.checkpoint("after_scrub")
    if _set_complete(deps, epoch):
        return _aborted(deps)
    deps.checkpoint("after_complete")
    return None


_STEPS = {
    "write": _step_write,
    "exec_verify": _step_exec_verify,
    "tick_verify": _step_tick_verify,
    "scrub": _step_scrub,
}


def run_migration(deps: MigrationDeps, *, force: bool = False) -> dict:
    """Drive the resumable state machine to "complete" or a failed:* park.

    Crash-safe + idempotent: reads state FRESH from disk each iteration (so a
    re-entry after a crash resumes from the last committed state), each step
    re-does its own work harmlessly, and plaintext survives until step 4. Returns
    a small result dict for the caller's log line.

    ``force`` (the manual "Re-run Keychain setup") starts even when auto-migration
    is disabled; the auto path leaves ``force`` False (DARK)."""
    cfg = deps.load_config()
    if not migration_should_run(cfg, available=deps.available(),
                                installed=deps.installed(),
                                auto_enabled=deps.auto_enabled, force=force):
        return {"action": "skipped",
                "state": keychain_store.migration_state(cfg)}

    # D3: snapshot the revert epoch. If a "Stop using the Keychain" commits while
    # this (possibly background-threaded) migration runs, the epoch changes and we
    # abort cleanly — never resurrecting the backend the user just left.
    start_epoch = keychain_store.revert_epoch(cfg)
    guard = 0
    while guard < 12:  # each step strictly advances or parks; ~5 is the real max
        guard += 1
        cfg = deps.load_config()
        if keychain_store.revert_epoch(cfg) != start_epoch:
            return _aborted(deps)
        state = keychain_store.migration_state(cfg)
        action = _action_for(state)
        if action is None:
            return {"action": "complete", "state": keychain_store.migration_state(cfg)}
        parked = _STEPS[action](deps, cfg, start_epoch)
        if parked is not None:
            return parked
    return {"action": "guard_exhausted",
            "state": keychain_store.migration_state(deps.load_config())}


# ---------------------------------------------------------------------------
# Backup scrub (§6.4). Overwrite the secret fields in every upgrade-backup config
# in place; do NOT delete the snapshots (§12.7 — their non-secret parts keep
# recovery value). Idempotent; unparseable/missing files skipped.
# ---------------------------------------------------------------------------

def _scrub_secret_fields(data: dict) -> bool:
    """Overwrite non-empty secret fields with SCRUB_SENTINEL. Returns True when
    anything changed. Mirrors the field set hydrate/strip walk PLUS the per-install
    self-mail HMAC key — leaving that plaintext in a Time-Machine-visible backup
    would re-open the Wave-6 self-mail forge surface the migration exists to
    close (ruling B3-3)."""
    if not isinstance(data, dict):
        return False
    changed = False

    def scrub(container: dict, field_name: str) -> None:
        nonlocal changed
        v = container.get(field_name)
        if isinstance(v, str) and v and not v.startswith(
                keychain_store.SENTINEL_PREFIX):
            container[field_name] = SCRUB_SENTINEL
            changed = True

    anthro = data.get("anthropic")
    if isinstance(anthro, dict):
        scrub(anthro, "api_key")
    smtp = data.get("smtp")
    if isinstance(smtp, dict):
        scrub(smtp, "password")
    for acct in data.get("accounts", []) or []:
        if isinstance(acct, dict):
            scrub(acct, "password")
    if isinstance(data.get(keychain_store.SELF_MAIL_SECRET_KEY), str):
        scrub(data, keychain_store.SELF_MAIL_SECRET_KEY)
    return changed


def scrub_upgrade_backups() -> int:
    """Scrub every ~/MailWarden-upgrade-backup/<stamp>/config/config.json in
    place (§6.4). Returns the number of files rewritten. Never raises on a single
    bad file — it is skipped."""
    root = paths.UPGRADE_BACKUP_DIR
    if not root.exists():
        return 0
    import json
    count = 0
    try:
        snapshots = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return 0
    for snap in snapshots:
        cfg_path = snap / "config" / "config.json"
        if not cfg_path.is_file():
            continue
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if _scrub_secret_fields(data):
            try:
                config_io.save_json_atomic(cfg_path, data)
                count += 1
            except OSError:
                continue
    return count


# ---------------------------------------------------------------------------
# Kill-switch actions (§7.2) — reachable ONLY at the keychain backend (the
# Settings group is hidden at the config backend; see is_settings_group_visible).
# ---------------------------------------------------------------------------

def revert_off_keychain(deps: MigrationDeps) -> dict:
    """"Stop using the Keychain" (§7.2). Read every item back to plaintext (the
    load inside update_config hydrates), blank any unreadable sentinel, flip the
    backend to "config", and delete the now-orphaned items when EVERY secret was
    recovered. Shares the exact core the CLI escape hatch uses
    (keychain_store.revert_config_to_plaintext). Returns
    {"unreadable": [account keys], "deleted": int}."""
    box: dict = {}

    def _m(cfg: dict) -> None:
        box["unreadable"] = keychain_store.revert_config_to_plaintext(cfg)

    deps.update_config(_m)
    unreadable = box.get("unreadable", [])
    deleted = 0
    if not unreadable and deps.available():
        try:
            deleted = deps.delete_all_items()
        except Exception:  # noqa: BLE001 — best effort; revert already succeeded
            deleted = 0
    return {"unreadable": unreadable, "deleted": deleted}


def restart_migration(deps: MigrationDeps) -> dict:
    """"Re-run Keychain setup" (§7.2) / the ACL "Repair keychain access" path
    (§7.1). Reset state to "none" (backend left as-is) and re-drive the machine
    with force=True.

    From a complete+sentinelized config with a READABLE keychain, this first
    write (via update_config, which saves the hydrated config while strip only
    sentinelizes at state=="complete") intentionally RE-MATERIALIZES the plaintext
    secrets into config.json — and that is correct: it restores the shadow-window
    invariant (a usable plaintext fallback exists) for the duration of the repair,
    so a crash mid-repair leaves filtering working and is self-healed on the next
    launch (migration_should_run now treats none+keychain as resumable, D2). Step
    1's write then rebuilds each item's ACL (delete+add) from the hydrated values,
    and step 4 re-sentinelizes. When the keychain is LOCKED, hydrate cannot read,
    the fields stay sentinels (no plaintext re-materializes), and the run parks at
    failed:items_write with the banner surfacing the locked cause (D4)."""
    cfg = deps.load_config()
    epoch = keychain_store.revert_epoch(cfg)
    _set_state(deps, epoch, STATE_NONE)
    return run_migration(deps, force=True)


def clear_stored_api_key(deps: MigrationDeps) -> dict:
    """"Clear stored key…" (scope addendum, supersedes carry-over C). Delete the
    Anthropic API-key keychain item and BLANK the config field — no sentinel left,
    so the field reads as "no key configured" and hydrate never resurrects it.
    Filtering stops until a new key is entered. This is the ONE explicit removal
    path; a blank Save still means "unchanged". Backend-gated: a no-op returning
    cleared:False at the config backend (dark). Returns {"cleared": bool}."""
    result = {"cleared": False}

    def _m(cfg: dict) -> None:
        if keychain_store.backend_of(cfg) != "keychain":
            return
        try:
            if deps.available():
                deps.delete_secret(keychain_store.api_key_account(),
                                   missing_ok=True)
        except Exception:  # noqa: BLE001 — clearing the field is the point
            pass
        cfg.setdefault("anthropic", {})["api_key"] = ""  # blank, NOT the sentinel
        result["cleared"] = True

    deps.update_config(_m)
    return result


# ---------------------------------------------------------------------------
# GUI-surface DECISION helpers (§7.1/§8). Pure (no Tk, no IO beyond the args) so
# they unit-test; the Dashboard/menu-bar widgets render whatever they return. All
# are inert at the config backend (dark ship).
# ---------------------------------------------------------------------------

# Draft copy (scope addendum: factual + succinct; per-string review waived).
API_KEY_KEYCHAIN_PLACEHOLDER = "••• stored in Keychain"

_BANNER_MIGRATION_FAILED = {
    "kind": "migration_failed",
    "title": "MailWarden couldn't finish moving your passwords to the Keychain",
    "detail": ("Your passwords are still safe and filtering is still working. "
               "You can try the move again from Settings → Keychain."),
    "action": "repair",
}
_BANNER_LOCKED = {
    "kind": "locked",
    "title": "MailWarden can't read your passwords from the Keychain",
    "detail": ("Your Mac's login keychain is locked. This usually means your "
               "login password and your keychain password don't match. Filtering "
               "is paused until it's unlocked."),
    "action": "open_keychain_access",
}
_BANNER_MISSING = {
    "kind": "missing",
    "title": "A saved password is missing from the Keychain",
    "detail": ("Re-enter the affected password in Accounts or Settings to restore "
               "it. Filtering is paused until then."),
    "action": "reenter",
}
_BANNER_ERROR = {
    "kind": "error",
    "title": "MailWarden couldn't use a password stored in the Keychain",
    "detail": ("Filtering is paused. Use “Repair keychain access” in "
               "Settings → Keychain to rebuild access to your saved "
               "passwords."),
    "action": "repair",
}
_BANNER_NO_API_KEY = {
    "kind": "no_api_key",
    "title": "No API key — spam filtering is paused",
    "detail": ("MailWarden needs your Anthropic API key to filter mail. Enter a "
               "new key in Settings to resume."),
    "action": "reenter",
}
# Shown for a failed:* park ONLY when the on-disk config still holds usable
# plaintext (the shadow window) — filtering genuinely keeps working from the
# fallback, so "still working" is TRUE of this state (D4).
_BANNER_MIGRATION_FAILED_SHADOW = _BANNER_MIGRATION_FAILED
# Shown for a failed:* park with NO usable plaintext and no specific status cause:
# filtering IS paused, so it must NOT claim to be working (D4).
_BANNER_MIGRATION_FAILED_CLOSED = {
    "kind": "migration_failed",
    "title": "MailWarden couldn't finish moving your passwords to the Keychain",
    "detail": ("Filtering is paused. Try the move again from "
               "Settings → Keychain."),
    "action": "repair",
}


def _has_usable_plaintext(config: dict) -> bool:
    """True when at least one secret field still holds a real plaintext value
    (non-empty, non-sentinel) — i.e. the shadow-window fallback is available and
    filtering is not fail-closed. Used to keep every banner string TRUE of the
    state it renders in (D4)."""
    def real(v) -> bool:
        return isinstance(v, str) and v.strip() != "" \
            and not v.startswith(keychain_store.SENTINEL_PREFIX)
    anthro = config.get("anthropic") or {}
    if real(anthro.get("api_key")):
        return True
    smtp = config.get("smtp") or {}
    if real(smtp.get("password")):
        return True
    for acct in config.get("accounts") or []:
        if isinstance(acct, dict) and real(acct.get("password")):
            return True
    return False


def _cause_banner(status: Optional[dict]) -> Optional[dict]:
    """The specific fail-closed cause banner for a not-ok status record, or None.
    Priority: locked > no-api-key > missing > error (§7.1)."""
    if not isinstance(status, dict) or status.get("ok"):
        return None
    if status.get("locked"):
        return dict(_BANNER_LOCKED)
    if status.get("empty"):
        return dict(_BANNER_NO_API_KEY)
    if status.get("missing"):
        return dict(_BANNER_MISSING)
    if status.get("errors"):
        return dict(_BANNER_ERROR)
    return None


def keychain_banner(config: dict, status: Optional[dict]) -> Optional[dict]:
    """The Dashboard banner to show, or None when there's nothing to surface.

    D1: a failed:* park is checked BEFORE the backend gate, because the two most
    likely failures (failed:items_write / failed:exec_verify) park with the
    backend STILL "config" (the flip is step 3) — gating on backend first would
    make them silent. Dark-safe: a config-backend beta never holds failed:*.

    Banner selection:
      * failed:* — if the run is fail-closed (a not-ok status AND no usable
        plaintext left on disk), show the specific cause (locked/no-key/missing/
        error) because filtering IS paused (D4); otherwise show the shadow
        "still working / try again" banner (true only while plaintext remains).
      * mid-migration (state not complete, not failed) at the keychain backend —
        quiet (shadow keeps filtering working; the machine self-heals).
      * complete — a not-ok keychain_status.json surfaces the specific cause."""
    state = keychain_store.migration_state(config)
    if state.startswith("failed:"):
        if _has_usable_plaintext(config):
            return dict(_BANNER_MIGRATION_FAILED_SHADOW)  # "still working" TRUE
        # Fail-closed: filtering IS paused — name the specific cause when the
        # status file has one, else a generic paused banner (never "working").
        cause = _cause_banner(status)
        return cause if cause is not None else dict(_BANNER_MIGRATION_FAILED_CLOSED)
    if keychain_store.backend_of(config) != "keychain":
        return None
    if state != STATE_COMPLETE:
        return None
    return _cause_banner(status)


def keychain_warning_active(config: dict, status: Optional[dict]) -> bool:
    """True when the menu bar should show a keychain warning state — i.e. the
    Dashboard would show a banner. Inert at the config backend."""
    return keychain_banner(config, status) is not None


MENU_BAR_WARNING_TEXT = "Keychain problem — open MailWarden"


def is_settings_group_visible(config: dict) -> bool:
    """Whether the Settings "Keychain (advanced)" group is shown (§7.2/§8/§12.8).
    Shown at the keychain backend AND in any failed:* migration state (D1) — a
    failed:items_write/exec_verify parks with the backend still "config", and the
    banner's "try the move again from Settings → Keychain" must point at a group
    that actually exists. Hidden in the dark config-backend beta (state "none"),
    so the Dashboard is byte-identical to today (ruling B3-4)."""
    return (keychain_store.backend_of(config) == "keychain"
            or keychain_store.migration_state(config).startswith("failed:"))


def _api_key_stored(config: dict) -> bool:
    """True when a real Anthropic API key is present (a hydrated real value, or a
    sentinel that resolves to one). False after a "Clear stored key…" (blank)."""
    api = (config.get("anthropic") or {}).get("api_key")
    return isinstance(api, str) and api.strip() != ""


API_KEY_NO_KEY_HINT = "No API key configured"


def api_key_placeholder_hint(config: dict) -> str:
    """Draft copy shown beside the (blank) API-key field at the keychain backend
    so a blank entry never reads as "no key configured" (carry-over A). Empty
    string at the config backend (dark). D5: after "Clear stored key…" no key is
    stored, so the "stored in Keychain" hint would be FALSE — show the accurate
    "No API key configured" instead."""
    if keychain_store.backend_of(config) != "keychain":
        return ""
    return (API_KEY_KEYCHAIN_PLACEHOLDER if _api_key_stored(config)
            else API_KEY_NO_KEY_HINT)


def show_help_entry(config: dict) -> bool:
    """Whether the Help tab's "Where are my passwords stored?" entry is shown.
    Keychain backend only (dark: hidden in the config-backend beta)."""
    return keychain_store.backend_of(config) == "keychain"


# ---------------------------------------------------------------------------
# Production wiring + the _main_inner entry point.
# ---------------------------------------------------------------------------

def _installed() -> bool:
    """Both trusted executables present at their canonical /Applications paths —
    i.e. we are the installed app, not a dev checkout / source run (§6.1)."""
    return (os.path.exists(keychain_store.APP_PATH)
            and os.path.exists(keychain_store.PY_PATH))


def _real_kickstart(label: str) -> None:
    uid = os.getuid()
    subprocess.run(["launchctl", "kickstart", f"gui/{uid}/{label}"],
                   capture_output=True, timeout=15)


def _read_status_file() -> Optional[dict]:
    return config_io.load_json(paths.KEYCHAIN_STATUS_PATH, None)


def build_deps(log: Callable[[str], None] = _noop_log) -> MigrationDeps:
    """Wire the real callables for the shipped app."""
    return MigrationDeps(
        load_config=config_io.load_config,
        update_config=config_io.update_config,
        write_secrets=keychain_store.write_configured_secrets,
        read_back=lambda cfg: keychain_store.verify_keys(cfg),
        spawn_verify=keychain_store.spawn_keychain_verify,
        kickstart=_real_kickstart,
        read_status=_read_status_file,
        scrub_backups=scrub_upgrade_backups,
        delete_secret=keychain_store.delete_secret,
        delete_all_items=keychain_store.delete_all_items,
        installed=_installed,
        available=keychain_store.available,
        now=lambda: datetime.now().timestamp(),
        sleep=time.sleep,
        auto_enabled=AUTO_MIGRATE_ENABLED,
        log=log,
    )


def maybe_run(startup_log) -> dict:
    """_main_inner hook (§6.1), Dashboard-process only. Wraps run_migration so any
    failure is non-fatal — a keychain hiccup must never block the Dashboard
    launch. DARK: with AUTO_MIGRATE_ENABLED False and no in-progress state (the
    only reality in a config-backend beta), migration_should_run short-circuits
    before any keychain op, so this is a cheap no-op."""
    try:
        deps = build_deps(log=lambda m: startup_log.step(m))
        result = run_migration(deps)
        startup_log.step(
            f"keychain migration: {result.get('action')} "
            f"state={result.get('state')}")
        return result
    except Exception as e:  # noqa: BLE001
        startup_log.step(
            f"keychain migration FAILED (non-fatal): {type(e).__name__}: {e}")
        return {"action": "error", "error": f"{type(e).__name__}: {e}"}

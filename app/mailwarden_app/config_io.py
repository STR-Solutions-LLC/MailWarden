# (c) 2026 STR Solutions, LLC. All rights reserved.
from __future__ import annotations
"""
Config and memory-file IO helpers.

Every write is atomic (mkstemp + os.replace) so a crash mid-write cannot
leave a corrupt file. Matches the pattern used in src/spam_filter.py
(`save_config_atomic`, `save_processed_ids`, etc.) so files written by the
UI are interchangeable with files written by the filter.
"""
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from . import file_lock
from . import paths


def now_iso() -> str:
    return datetime.now().isoformat()


def save_json_atomic(target: Path, data: Any) -> None:
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(target))
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_json(target: Path, default: Any) -> Any:
    target = Path(target)
    if not target.exists():
        return default
    try:
        with target.open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


# ---------------------------------------------------------------------------
# Config schema — the exact shape the filter reads
# ---------------------------------------------------------------------------

# Schema matches what spam_filter.py reads:
#   - flat per-account fields (imap_host, imap_port, username, password,
#     junk_folder, folders_to_scan, enabled, name)
#   - single global SMTP block at the top level (smtp.host, smtp.port, etc.)
DEFAULT_CONFIG: dict = {
    "accounts": [],
    "anthropic": {
        "api_key": "",
        "model": "claude-haiku-4-5-20251001",
        "confidence_threshold": 0.85,
    },
    "filter": {
        "dry_run": True,
        "max_emails_per_run": 100,
        # How often the filter actually checks mail. launchd wakes the filter
        # every 5 minutes (a fixed floor in the signed read-only plist); the
        # filter reads this value at runtime and an elapsed-time gate in
        # spam_filter.run_filter() skips any scheduled wake that fires sooner
        # than interval_minutes after the last real run. The UI clamps this to
        # a sane range (5–360 minutes).
        "interval_minutes": 15,
    },
    "smtp": {
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "from_address": "",
        "use_starttls": True,
    },
    "summary": {
        "recipient": "",
        "hour": 8,
        "minute": 0,
    },
    "whitelist": {"folder": None},
    "blacklist": {"folder": None},
    "signal_learner": {
        "enabled": True,
    },
    "eula": {
        "current_version": "1.0",
        "sent_to_accounts": {},
    },
    "ui": {
        "menu_bar_enabled": True,
        "update_check_last_run": "",
        "dashboard_show_welcome_tip": True,
        # On Dashboard launch, check each account for the "Train MailWarden"
        # IMAP folder and offer to create it if missing. Users who've already
        # declined or set up their folders elsewhere can turn this off.
        "prompt_missing_train_folder": True,
    },
}


def new_account_entry(
    name: str,
    imap_host: str,
    imap_port: int,
    imap_username: str,
    imap_password: str,
    junk_folder: str,
    folders_to_scan: list[str] | None = None,
    enabled: bool = True,
    spam_action: str = "junk",
) -> dict:
    """Produce a per-account dict in the flat schema the filter reads."""
    return {
        "name": name,
        "enabled": enabled,
        "imap_host": imap_host,
        "imap_port": imap_port,
        "username": imap_username,
        "password": imap_password,
        "junk_folder": junk_folder,
        "folders_to_scan": folders_to_scan or ["INBOX"],
        "spam_action": spam_action,  # "junk" | "trash" | "delete"
    }


def smtp_config_from_account(
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    from_address: str,
    use_starttls: bool = True,
) -> dict:
    """Produce the global smtp dict the filter reads."""
    return {
        "host": smtp_host,
        "port": smtp_port,
        "username": smtp_username,
        "password": smtp_password,
        "from_address": from_address,
        "use_starttls": use_starttls,
    }


def load_config() -> dict:
    """Load config.json if present, else return a deep copy of DEFAULT_CONFIG.

    Migration: older configs lack per-account spam_action. Treat missing as
    "junk" so existing behavior is preserved on upgrade.
    """
    import copy
    if paths.CONFIG_PATH.exists():
        try:
            with paths.CONFIG_PATH.open(encoding="utf-8") as f:
                data = json.load(f)
            # Back-fill spam_action on accounts created before this field existed.
            for acct in data.get("accounts", []):
                acct.setdefault("spam_action", "junk")
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return copy.deepcopy(DEFAULT_CONFIG)


def save_config(config: dict) -> None:
    save_json_atomic(paths.CONFIG_PATH, config)
    # 600 — readable only by the user (contains API key + email passwords)
    try:
        os.chmod(paths.CONFIG_PATH, 0o600)
    except OSError:
        pass


def update_config(mutator) -> dict:
    """Atomic read-modify-write of config.json under the cross-process lock.

    Loads the LATEST config FRESH inside the lock, applies ``mutator(config)``
    (which mutates the dict in place — its return value is ignored), saves, and
    returns the saved config. Holding file_lock.locked() across the whole span
    means a concurrent writer (the filter's command handlers, the EULA save, a
    peer UI process) cannot land a change between this load and save that the
    blind save would silently revert (audit C7). The mutator must touch ONLY the
    keys this caller intends to change — everything else it reads fresh and
    re-saves untouched. A TimeoutError from locked() (only if a peer hangs >30s)
    propagates to the caller's existing error handling.
    """
    with file_lock.locked(paths.CONFIG_PATH):
        config = load_config()
        mutator(config)
        save_config(config)
        return config


# ---------------------------------------------------------------------------
# Memory-file helpers
# ---------------------------------------------------------------------------

def load_whitelist() -> dict:
    return load_json(
        paths.WHITELIST_PATH,
        {"version": "1.0", "addresses": [], "domains": [], "last_updated": ""},
    )


def save_whitelist(wl: dict) -> None:
    wl["last_updated"] = now_iso()
    save_json_atomic(paths.WHITELIST_PATH, wl)


def load_blacklist() -> dict:
    return load_json(
        paths.BLACKLIST_PATH,
        {"version": "1.0", "addresses": [], "display_names": [], "domains": [],
         "subject_keywords": [], "last_updated": ""},
    )


def save_blacklist(bl: dict) -> None:
    bl["last_updated"] = now_iso()
    save_json_atomic(paths.BLACKLIST_PATH, bl)


# Map a "Block this sender" entry kind to the blacklist.json list it lives in.
# (display_name / subject_keyword are here for completeness; the block-sender
# action only uses address/domain, but the writer is general.)
_BLOCK_KIND_TO_FIELD = {
    "address": "addresses",
    "domain": "domains",
    "display_name": "display_names",
    "subject_keyword": "subject_keywords",
}


def add_blocklist_entry(value: str, kind: str, scope) -> bool:
    """Write ONE scoped block-list entry into blacklist.json (PB2).

    ``kind`` is "address" | "domain" | "display_name" | "subject_keyword".
    ``scope`` is "all" or a list of account usernames — the SAME shape used by
    ai_refinement scope and read by spam_filter._blacklist_entry_in_scope.

    Representation (migration-safe): the entry is stored as an OBJECT
    ``{"value": <normalized value>, "scope": <scope>}``. Legacy plain-string
    entries already in the file are left untouched and keep working as global
    blocks (spam_filter normalizes both shapes). Domains are normalized to a
    bare lowercased domain (leading '@' stripped); addresses/keywords are
    lowercased/trimmed.

    Idempotent: if an entry with the same normalized value already exists (in
    EITHER shape), its scope is updated in place rather than duplicating the
    value. Returns True if the file was changed, False on a bad kind/empty value.
    """
    # Lock the whole load→modify→save span (C7): a concurrent writer of
    # blacklist.json (the filter's "block sender" handler, a list-tab edit)
    # cannot land a change between the fresh load and the save below.
    with file_lock.locked(paths.BLACKLIST_PATH):
        return _add_blocklist_entry_locked(value, kind, scope)


def _add_blocklist_entry_locked(value: str, kind: str, scope) -> bool:
    """Unlocked core of add_blocklist_entry — the caller MUST already hold the
    blacklist.json sidecar lock. flock is not re-entrant across two fds in one
    process, so a caller that already holds the lock (e.g.
    apply_blocklist_proposal_from_pending) calls this directly instead of the
    public wrapper, which would deadlock against itself. Same logic, same
    return contract as add_blocklist_entry."""
    field = _BLOCK_KIND_TO_FIELD.get((kind or "").strip().lower())
    if field is None:
        return False
    v = (value or "").strip().lower()
    if field == "domains":
        v = v.lstrip("@")
    if not v:
        return False

    bl = load_blacklist()
    items = bl.setdefault(field, [])

    def _entry_value(item) -> str:
        raw = item.get("value") if isinstance(item, dict) else item
        if not isinstance(raw, str):
            return ""
        s = raw.strip().lower()
        return s.lstrip("@") if field == "domains" else s

    # Update existing row (either shape) to the new scope, de-duping by value.
    for i, item in enumerate(items):
        if _entry_value(item) == v:
            items[i] = {"value": v, "scope": scope}
            save_blacklist(bl)
            return True

    items.append({"value": v, "scope": scope})
    save_blacklist(bl)
    return True


def load_token_usage() -> dict:
    return load_json(
        paths.TOKEN_USAGE_PATH,
        {
            "version": "1.0",
            "lifetime_tokens": 0,
            "lifetime_cost_usd": 0.0,
            "daily": {},
            "pre_classifier_skips": 0,
            "last_updated": "",
        },
    )


def load_pending_signals() -> dict:
    return load_json(paths.PENDING_SIGNALS_PATH, {"version": "1.0", "conversations": []})


def save_pending_signals(data: dict) -> None:
    save_json_atomic(paths.PENDING_SIGNALS_PATH, data)


def load_signals() -> dict:
    return load_json(paths.SIGNALS_PATH, {"signals": {}, "ai_refinements": []})


def save_signals(data: dict) -> None:
    save_json_atomic(paths.SIGNALS_PATH, data)


# ---------------------------------------------------------------------------
# AI-refinement helpers
# ---------------------------------------------------------------------------
# Active refinements live inside signals.json under the "ai_refinements"
# array. The full history of events (proposed / applied / rejected /
# expired / reinforced / deleted) is appended as JSONL to
# ~/MailWarden/memory/signal_refinements.log so the Dashboard's history
# section is cheap to render without reconstructing state.


def list_active_refinements() -> list[dict]:
    data = load_signals()
    return [r for r in data.get("ai_refinements", [])
            if r.get("status", "active") == "active"]


def append_refinement_log(event: dict) -> None:
    """Append one JSON record to signal_refinements.log.

    event schema (loose — Dashboard tolerates missing fields):
      {ts, event, id, sfid?, headline?, evidence?, source?, reason?}
    """
    import json as _json
    paths.REFINEMENTS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with paths.REFINEMENTS_LOG.open("a", encoding="utf-8") as f:
        f.write(_json.dumps(event, ensure_ascii=False) + "\n")


def load_refinement_log(limit: int = 500) -> list[dict]:
    """Return the last `limit` events, newest first."""
    import json as _json
    if not paths.REFINEMENTS_LOG.exists():
        return []
    try:
        lines = paths.REFINEMENTS_LOG.read_text(encoding="utf-8",
                                                  errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(_json.loads(line))
        except _json.JSONDecodeError:
            continue
    out.reverse()
    return out


def delete_active_refinement(refinement_id: str, source: str = "dashboard",
                              reason: str = "") -> bool:
    """Remove a refinement from the active list. Logs the deletion.
    Returns True if something was deleted, False if id wasn't found."""
    # Lock the signals.json RMW span (C7): the learner's merge-save or a
    # concurrent Dashboard edit cannot race this delete and resurrect the row.
    with file_lock.locked(paths.SIGNALS_PATH):
        data = load_signals()
        remaining = []
        found = None
        for r in data.get("ai_refinements", []):
            if r.get("id") == refinement_id:
                found = r
                continue
            remaining.append(r)
        if found is None:
            return False
        data["ai_refinements"] = remaining
        save_signals(data)
    append_refinement_log({
        "ts": now_iso(),
        "event": "deleted",
        "id": refinement_id,
        "headline": found.get("headline", ""),
        "source": source,
        "reason": reason,
    })
    return True


def set_refinement_scope(refinement_id: str, scope) -> bool:
    """Set the per-account ``scope`` on an active refinement and persist.

    ``scope`` is "all" or a list of account usernames (the value produced by
    dashboard.scope_from_toggle_state). Returns True if a refinement with that
    id was found and updated, False otherwise. Used by the Dashboard's
    per-account toggle row so a scope change takes effect on the next filter
    tick without an email round-trip.
    """
    # Lock the signals.json RMW span (C7): a fresh read under the lock means a
    # concurrent learner merge-save / Dashboard edit isn't clobbered by this one.
    with file_lock.locked(paths.SIGNALS_PATH):
        data = load_signals()
        for r in data.get("ai_refinements", []):
            if r.get("id") == refinement_id:
                r["scope"] = scope
                save_signals(data)
                return True
        return False


def apply_refinement_from_pending(sfid: str, source: str = "dashboard") -> dict | None:
    """Move a pending spam_example_proposal SFID into active refinements.

    Runs the same state transitions as the email-YES flow in spam_filter.py
    so Dashboard-initiated approvals and email-initiated approvals end up
    in an identical state. Returns the applied refinement dict, or None
    when the SFID wasn't found / wasn't an approvable kind / was already
    resolved.
    """
    # ONE lock over BOTH files for the whole operation (C7). file_lock.locked
    # sorts the two sidecar paths into a fixed order internally, so this can
    # never deadlock against another op that takes the same pair in the opposite
    # order. Fresh reads under the lock mean a concurrent learner save or a
    # parallel approval cannot be clobbered.
    with file_lock.locked(paths.PENDING_SIGNALS_PATH, paths.SIGNALS_PATH):
        pending = load_pending_signals()
        conv = None
        for c in pending.get("conversations", []):
            if c.get("id") == sfid:
                conv = c
                break
        if conv is None:
            return None
        if conv.get("status") not in ("awaiting_reply",):
            return None
        if conv.get("kind") != "spam_example_proposal":
            return None
        refinement = conv.get("proposed_refinement")
        if not isinstance(refinement, dict):
            return None

        # Add to active list
        data = load_signals()
        refinements = data.setdefault("ai_refinements", [])
        existing_ids = {r.get("id") for r in refinements}
        if refinement.get("id") in existing_ids:
            # Already active — treat as no-op but still mark conv resolved
            pass
        else:
            refinement = dict(refinement)
            # P1 approval backstop: proposals created before scope-capture
            # existed carry no scope. Bind them to the inbox that forwarded the
            # example so the rule does not silently leak onto every account.
            # Only fills a MISSING scope key — never overwrites a scope the
            # proposal already has (including an empty list, a deliberate
            # "no accounts").
            if "scope" not in refinement:
                conv_forwarder = (conv.get("forwarder") or "").strip().lower()
                if conv_forwarder:
                    refinement["scope"] = [conv_forwarder]
            refinement["status"] = "active"
            refinement.setdefault("first_learned", now_iso())
            refinement.setdefault("last_reinforced", now_iso())
            refinement.setdefault("match_count", 1)
            refinements.append(refinement)
            save_signals(data)

        conv["status"] = "approved"
        conv["resolution"] = "approved"
        conv.setdefault("conversation_history", []).append({
            "role": "system",
            "timestamp": now_iso(),
            "content": f"Approved via {source}",
        })
        save_pending_signals(pending)
    append_refinement_log({
        "ts": now_iso(),
        "event": "applied",
        "id": refinement.get("id"),
        "sfid": sfid,
        "headline": refinement.get("headline", ""),
        "source": source,
    })
    return refinement


def apply_blocklist_proposal_from_pending(sfid: str,
                                          source: str = "dashboard") -> dict | None:
    """Approve a pending "Block this sender" proposal (PB2).

    Parallels apply_refinement_from_pending, but instead of activating an
    ai_refinement it WRITES the scoped block-list entry to blacklist.json (via
    add_blocklist_entry) so the block is enforced per-account on the next filter
    tick. Returns the written entry dict, or None when the SFID wasn't found /
    wasn't a block_sender_proposal / was already resolved.
    """
    # ONE lock over BOTH files for the whole operation (C7), sorted internally
    # so it can't deadlock against a peer taking the same pair in the other
    # order. The blacklist write below uses the UNLOCKED core
    # (_add_blocklist_entry_locked) on purpose: flock is not re-entrant across
    # two fds in one process, so calling the locking add_blocklist_entry here
    # would block forever waiting on the lock this very call already holds.
    with file_lock.locked(paths.PENDING_SIGNALS_PATH, paths.BLACKLIST_PATH):
        pending = load_pending_signals()
        conv = None
        for c in pending.get("conversations", []):
            if c.get("id") == sfid:
                conv = c
                break
        if conv is None:
            return None
        if conv.get("status") not in ("awaiting_reply",):
            return None
        if conv.get("kind") != "block_sender_proposal":
            return None
        entry = conv.get("blocklist_entry")
        if not isinstance(entry, dict) or not entry.get("value"):
            return None

        _add_blocklist_entry_locked(entry.get("value", ""),
                                    entry.get("kind", "domain"),
                                    entry.get("scope", "all"))

        conv["status"] = "approved"
        conv["resolution"] = "approved"
        conv.setdefault("conversation_history", []).append({
            "role": "system",
            "timestamp": now_iso(),
            "content": f"Block-sender approved via {source}",
        })
        save_pending_signals(pending)
    append_refinement_log({
        "ts": now_iso(),
        "event": "applied",
        "id": conv.get("id"),
        "sfid": sfid,
        "headline": f"Block sender {entry.get('kind', '')}: {entry.get('value', '')}",
        "source": source,
    })
    return entry


def reject_pending(sfid: str, source: str = "dashboard",
                    reason: str = "") -> bool:
    """Mark a pending SFID proposal as rejected. Works for any kind."""
    # Lock the pending_signals.json RMW span (C7): a concurrent filter command
    # handler / parallel approval cannot race this reject and lose either edit.
    with file_lock.locked(paths.PENDING_SIGNALS_PATH):
        pending = load_pending_signals()
        conv = None
        for c in pending.get("conversations", []):
            if c.get("id") == sfid:
                conv = c
                break
        if conv is None or conv.get("status") not in ("awaiting_reply",):
            return False
        conv["status"] = "rejected"
        conv["resolution"] = "rejected"
        conv.setdefault("conversation_history", []).append({
            "role": "system",
            "timestamp": now_iso(),
            "content": f"Rejected via {source}" + (f": {reason}" if reason else ""),
        })
        save_pending_signals(pending)
    refinement_id = (conv.get("proposed_refinement") or {}).get("id", "")
    append_refinement_log({
        "ts": now_iso(),
        "event": "rejected",
        "id": refinement_id,
        "sfid": sfid,
        "source": source,
        "reason": reason,
    })
    return True


def withdraw_pending(sfid: str, source: str = "dashboard") -> bool:
    """Remove a pending proposal the user no longer wants to decide on."""
    # Lock the pending_signals.json RMW span (C7): the fresh read under the lock
    # means a concurrent writer's change to the conversation list isn't erased.
    with file_lock.locked(paths.PENDING_SIGNALS_PATH):
        pending = load_pending_signals()
        before = len(pending.get("conversations", []))
        pending["conversations"] = [c for c in pending.get("conversations", [])
                                     if c.get("id") != sfid]
        if len(pending["conversations"]) == before:
            return False
        save_pending_signals(pending)
    append_refinement_log({
        "ts": now_iso(),
        "event": "withdrawn",
        "sfid": sfid,
        "source": source,
    })
    return True


def load_installer_state() -> dict:
    return load_json(
        paths.INSTALLER_STATE_PATH,
        {
            "installer_version": "1.0",
            "filter_version": "1.5",
            "installed_at": "",
            "last_upgrade_at": "",
        },
    )


def save_installer_state(state: dict) -> None:
    save_json_atomic(paths.INSTALLER_STATE_PATH, state)

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
import re
import secrets
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
        # classify_mode "cascade" = two-model double-check: screen_model
        # judges every email; confirm_model re-judges anything the screen
        # would junk, and mail is junked only when both agree (rescue-only).
        # "single" runs `model` on every email like pre-cascade releases.
        # load_config's _deep_merge back-fills these keys onto older saved
        # configs, so ALL existing installs move to the cascade on upgrade
        # (Matt's decision, 2026-07-02); `model` is retained and used only
        # when classify_mode == "single".
        "classify_mode": "cascade",
        "model": "claude-haiku-4-5-20251001",
        "screen_model": "claude-haiku-4-5-20251001",
        "confirm_model": "claude-sonnet-4-6",
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
        "confidence_threshold": 0.85,
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
        # The daily report runs statically at 08:00 via the SMAppService plist;
        # there is no configurable report time. Legacy configs may still carry
        # summary.hour / summary.minute — nothing reads them, so they are
        # silently ignored (never crash).
        "recipient": "",
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


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Return overlay with any missing keys back-filled from base, recursively.

    Existing overlay values are never overwritten — user config wins.
    """
    import copy
    result = dict(overlay)
    for key, base_val in base.items():
        if key not in result:
            result[key] = copy.deepcopy(base_val)
        elif isinstance(base_val, dict) and isinstance(result[key], dict):
            result[key] = _deep_merge(base_val, result[key])
    return result


def load_config() -> dict:
    """Load config.json if present, else return a deep copy of DEFAULT_CONFIG.

    Migrations applied on load:
    - Back-fill spam_action on accounts created before this field existed.
    - C4: move confidence_threshold from anthropic → filter block.
    - M16: back-fill any keys added to DEFAULT_CONFIG since config was saved.
    """
    import copy
    if paths.CONFIG_PATH.exists():
        try:
            with paths.CONFIG_PATH.open(encoding="utf-8") as f:
                data = json.load(f)
            # Back-fill spam_action on accounts created before this field existed.
            for acct in data.get("accounts", []):
                acct.setdefault("spam_action", "junk")
            # C4: migrate confidence_threshold from anthropic → filter block.
            anthropic_block = data.get("anthropic", {})
            filter_block = data.setdefault("filter", {})
            if "confidence_threshold" in anthropic_block and \
               "confidence_threshold" not in filter_block:
                filter_block["confidence_threshold"] = \
                    anthropic_block.pop("confidence_threshold")
            # M16: fill in any schema keys missing from this (older) saved config.
            data = _deep_merge(DEFAULT_CONFIG, data)
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


# ---------------------------------------------------------------------------
# Provenance-tagged deterministic entries for authored "Unwanted Categories"
# rules.
#
# When an authored rule names exact subject tokens / sender addresses / domains,
# those are enforced by the deterministic keyword & blacklist gates (which fire
# BEFORE the AI classifier) instead of by the prompt. Each such entry is written
# in the EXISTING migration-safe object shape {"value","scope"} with ONE added
# key, "provenance" = a LIST of PER-OWNER records {"id","scope"} (MULTI-OWNER).
# The engine's _normalize_block_entries reads only value+scope and ignores extra
# keys, so old plain-string and old {"value","scope"} entries keep working
# unchanged and no store rewrite is needed. "provenance" is used ONLY here, to
# cascade-remove a rule's own entries on retire/delete: an entry is dropped only
# when its LAST owner is removed, and the entry's effective "scope" is recomputed
# as the UNION OF THE REMAINING OWNERS' scopes on every add AND remove — so a
# token two rules with different account scopes share narrows back to the
# survivor's scope when one is deleted (no over-block), and a hand-added block
# (no provenance) is NEVER touched. Legacy string / list-of-ids provenance is
# read as owners inheriting the entry's current scope, then migrated on write.
#
# The four cascade helpers here (config_io) and their engine twins
# (spam_filter.add_ai_provenance_entries_local / remove_ai_provenance_entries_local
# + _provenance_owners / _union_scopes) MUST stay in sync — the two trees never
# import each other and share only these JSON sidecars, so the per-owner-scope
# logic is duplicated verbatim. If you edit one copy, edit the other.
# ---------------------------------------------------------------------------

# The blacklist fields an authored marker can land in (subset of
# _BLOCK_KIND_TO_FIELD — display_name is not an authored marker kind).
_AUTHORED_MARKER_FIELDS = {
    "subject_keyword": "subject_keywords",
    "address": "addresses",
    "domain": "domains",
}


def _blocklist_value_of(item, *, strip_at: bool) -> str:
    """Normalized comparable value of a blacklist item (string OR {"value"...})."""
    raw = item.get("value") if isinstance(item, dict) else item
    if not isinstance(raw, str):
        return ""
    s = raw.strip().lower()
    return s.lstrip("@") if strip_at else s


def _provenance_owners(entry) -> list:
    """The authored-rule owners of a blacklist entry, each as {"id","scope"} —
    PER-OWNER scope, so the entry's effective scope can be recomputed as the
    union of the REMAINING owners after one is removed (no over-block). Read
    every shape:
      - no "provenance" key            -> [] (hand-added / PB2 block; sacrosanct)
      - legacy single-id STRING        -> [{id, <entry scope>}]  (inherit)
      - legacy LIST of id strings      -> [{id, <entry scope>}, ...] (inherit)
      - current LIST of {"id","scope"} -> as-is
    Legacy owners inherit the entry's current top-level scope (the best info
    available); the shape is migrated to {"id","scope"} on the next write."""
    if not isinstance(entry, dict):
        return []
    prov = entry.get("provenance")
    if prov is None:
        return []
    entry_scope = entry.get("scope", "all")
    owners = []
    if isinstance(prov, str):
        if prov.strip():
            owners.append({"id": prov, "scope": entry_scope})
        return owners
    if isinstance(prov, list):
        for p in prov:
            if isinstance(p, dict) and isinstance(p.get("id"), str) \
                    and p["id"].strip():
                owners.append({"id": p["id"],
                               "scope": p.get("scope", entry_scope)})
            elif isinstance(p, str) and p.strip():
                owners.append({"id": p, "scope": entry_scope})
    return owners


def _union_scopes(scopes) -> "str | list":
    """Union of an iterable of block-list scopes. "all" (or a None scope, which
    the gate treats as global) absorbs everything; otherwise union the account
    lists, preserving first-seen order. Empty input -> "all" (defensive; callers
    only union a non-empty owner set)."""
    out = []
    any_seen = False
    for s in scopes:
        any_seen = True
        if s is None or s == "all":
            return "all"
        items = list(s) if isinstance(s, (list, tuple)) else [s]
        for a in items:
            if a not in out:
                out.append(a)
    return out if any_seen else "all"


def write_provenance_entries(entries, scope, provenance) -> int:
    """Write authored-rule deterministic markers into blacklist.json under the
    MULTI-OWNER, PER-OWNER-SCOPE provenance model. Locked RMW. Returns the count
    of entries created or adopted.

    ``entries`` is a list of {"kind": "subject_keyword"|"address"|"domain",
    "value": <str>}. For each value:
      - absent   -> create {"value","scope","provenance":[{"id","scope"}]}.
      - owned    -> ADOPT: add/refresh this rule's {"id","scope"} owner record
        and recompute the entry's effective scope = union of ALL owners' scopes,
        migrating any legacy string/list-of-ids provenance to {"id","scope"}.
      - hand-added (plain string / dict with no provenance) -> LEFT UNTOUCHED:
        the rule takes NO ownership, so a later delete can never take a hand
        entry; it already enforces the value."""
    if not entries:
        return 0
    with file_lock.locked(paths.BLACKLIST_PATH):
        bl = load_blacklist()
        changed = 0
        for e in entries:
            kind = (e.get("kind") or "").strip().lower()
            field = _AUTHORED_MARKER_FIELDS.get(kind)
            if field is None:
                continue
            strip_at = (field == "domains")
            v = (e.get("value") or "").strip().lower()
            if strip_at:
                v = v.lstrip("@")
            if not v:
                continue
            items = bl.setdefault(field, [])
            existing = next(
                (it for it in items
                 if _blocklist_value_of(it, strip_at=strip_at) == v), None)
            if existing is None:
                items.append({"value": v, "scope": scope,
                              "provenance": [{"id": provenance, "scope": scope}]})
                changed += 1
                continue
            owners = _provenance_owners(existing)
            if not owners:
                # Hand-added / PB2 block — sacrosanct. No ownership taken.
                continue
            owners = [o for o in owners if o["id"] != provenance]
            owners.append({"id": provenance, "scope": scope})
            existing["provenance"] = owners
            existing["scope"] = _union_scopes([o["scope"] for o in owners])
            changed += 1
        if changed:
            save_blacklist(bl)
    return changed


def remove_provenance_entries(provenance) -> int:
    """Drop this rule's ownership of its deterministic blacklist entries (MULTI-
    OWNER, PER-OWNER SCOPE). For each entry this rule owns, remove its owner
    record and RECOMPUTE the entry's effective scope as the union of the
    REMAINING owners' scopes — so an entry a rule scoped to account X shared
    narrows back to the survivors' accounts and X mail is no longer junked. The
    entry is deleted only when its LAST owner is removed. Hand-added entries (no
    provenance) are never touched. Locked RMW. Returns the count of entries FULLY
    removed (last owner gone)."""
    removed = 0
    with file_lock.locked(paths.BLACKLIST_PATH):
        bl = load_blacklist()
        changed = False
        for field in _AUTHORED_MARKER_FIELDS.values():
            items = bl.get(field)
            if not isinstance(items, list):
                continue
            new_items = []
            for it in items:
                owners = _provenance_owners(it)
                if any(o["id"] == provenance for o in owners):
                    changed = True
                    remaining = [o for o in owners if o["id"] != provenance]
                    if remaining:
                        it["provenance"] = remaining
                        it["scope"] = _union_scopes(
                            [o["scope"] for o in remaining])
                        new_items.append(it)
                    else:
                        removed += 1  # last owner -> entry dropped
                else:
                    new_items.append(it)
            bl[field] = new_items
        if changed:
            save_blacklist(bl)
    return removed


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


# Retired shipped-default signals (fix a-1). Stripped in-memory on every load so
# existing installs whose memory/signals.json inherited them stop surfacing them
# without a forced disk rewrite. EXACT-match only — never substring — so a
# genuine user-taught signal is never collateral. Keep in sync across the 4 copies.
_RETIRED_DEFAULT_SIGNALS = frozenset({
    "Benign conversational text block (meeting scheduling, personal reflection) prepended before promotional/scam content - used as filter evasion",
    "CSS class names using random nature/object word combinations (e.g., 'nebula-quartz', 'pebble-orbit', 'aurora-cinder', 'thistle-comet') in HTML emails",
    "Mismatch between casual/personal opening paragraphs and promotional closing content",
    "Points/rewards expiration urgency with specific dollar amounts ($100)",
})


def scrub_retired_signals(data: dict) -> dict:
    """Strip retired shipped-default signals in-memory. Returns the same dict."""
    if not isinstance(data, dict):
        return data
    sig = data.get("signals")
    if isinstance(sig, dict):
        for key in ("hard_signals", "soft_signals"):
            vals = sig.get(key)
            if isinstance(vals, list):
                sig[key] = [s for s in vals if s not in _RETIRED_DEFAULT_SIGNALS]
    return data


def load_signals() -> dict:
    return scrub_retired_signals(
        load_json(paths.SIGNALS_PATH, {"signals": {}, "ai_refinements": []}))


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


# Provenance marker for a curate rule the OWNER authored directly in the
# Unwanted Categories editor (typed, no example email, no Claude call), as
# opposed to one the learner derived from a forwarded/taught example. Same
# rule_class + storage + prompt path as a learned curate rule — only the
# source differs, so the editor can list/manage authored rules on their own.
AUTHORED_SOURCE = "user_authored"


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
    # Cascade: drop this authored rule's deterministic blacklist entries (only
    # its own provenance-tagged rows; hand-added blocks are never touched).
    if found.get("source") == AUTHORED_SOURCE:
        remove_provenance_entries(refinement_id)
    return True


def list_retired_refinements() -> list[dict]:
    """Retired (email-dropped) refinements, for the Dashboard's Dropped-rules
    panel. Mirrors list_active_refinements' shape but with an EXACT predicate:
    only records explicitly marked "retired" count — an absent status must NOT
    (unlike list_active_refinements, which treats an absent status as active).
    The "retired" status is set by the email DROP corridor
    (spam_filter.retire_ai_refinement) AND by the Dashboard/editor disable toggle
    (config_io.retire_refinement); the Dashboard Delete button removes the record
    outright, so a deleted rule never lands here."""
    return [r for r in load_signals().get("ai_refinements", [])
            if r.get("status") == "retired"]


def restore_refinement(refinement_id: str, source: str = "dashboard") -> dict | None:
    """Config_io twin of spam_filter.unretire_ai_refinement — MUST stay in sync
    with it (the two trees never import each other, so the semantics are
    duplicated; the engine body is the source of truth). RESTORE a dropped rule:
    flip its ai_refinement status from "retired" back to "active". The retired
    record was never deleted, so this is a pure status flip — the rule is used
    again on the next filter tick. Returns the reactivated refinement dict on
    success, or None if no matching RETIRED rule was found (missing OR already
    active — idempotent, safe on repeated clicks)."""
    # Lock the signals.json RMW span (C7): a fresh read under the lock means a
    # concurrent learner merge-save / Dashboard edit isn't clobbered by this one.
    restored = None
    with file_lock.locked(paths.SIGNALS_PATH):
        data = load_signals()
        for r in data.get("ai_refinements", []) or []:
            if r.get("id") == refinement_id and r.get("status") == "retired":
                r["status"] = "active"
                r.pop("retired_at", None)
                r["last_reinforced"] = now_iso()
                restored = r
                break
        if restored is not None:
            save_signals(data)
    if restored is not None:
        append_refinement_log({
            "ts": now_iso(),
            "event": "restored_by_owner",
            "id": refinement_id,
            "headline": restored.get("headline", ""),
            "source": source,
        })
        # Cascade: re-add the authored rule's deterministic blacklist entries
        # that its retire removed, honoring the rule's current scope.
        if restored.get("source") == AUTHORED_SOURCE:
            entries = restored.get("deterministic_entries") or []
            if entries:
                write_provenance_entries(entries, restored.get("scope", "all"),
                                         refinement_id)
    return restored


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


# ---------------------------------------------------------------------------
# Owner-authored "Unwanted Categories" curate rules (Batch C).
#
# These reuse the EXISTING curate refinement mechanism end-to-end — same
# rule_class ("curate"), same storage (signals.json[ai_refinements]), same
# prompt injection (spam_filter._build_learned_lines renders them on the
# identical "USER PREFERENCE (curate)" path a learned curate rule uses). The
# ONLY differences: the owner types the category description directly (no
# example email, no Claude call), so the record is created here rather than by
# the learner; and source==AUTHORED_SOURCE marks the provenance so the editor
# can manage authored rules separately and the learner/contradiction guard is
# never surprised. Enable/disable reuse the retire/restore status flip; delete
# reuses delete_active_refinement.
# ---------------------------------------------------------------------------


def build_authored_curate_refinement(refinement_id: str, description: str,
                                     scope, enforcement: dict | None = None) -> dict | None:
    """PURE (no IO). Build an ACTIVE curate ai_refinement authored directly by
    the owner. Mirrors the LEARNED curate record shape
    (learn_signals._build_refinement with verdict "spam" + rule_class "curate")
    so it flows through the identical classifier path; only the provenance
    differs (source=AUTHORED_SOURCE, evidence empty, no Claude rationale).

    ``enforcement`` (optional) is the classifier from breadth_advisor.
    extract_enforcement. When supplied it adds three fields the engine reads:
      - "enforcement": "deterministic" | "mixed" | "ai" — how the rule is applied
        (deterministic-only rules are NOT injected into the prompt; mixed rules
        inject only their residual; ai rules inject the whole headline).
      - "residual_text": the judgment half a MIXED rule injects.
      - "deterministic_entries": the {kind,value} markers written to the keyword/
        blacklist store (kept on the record so a RESTORE can re-add them).
    When ``enforcement`` is None the record keeps the legacy shape and behaves as
    today (full-headline injection, no deterministic entries).

    Returns None when ``description`` is blank — a headline-less refinement is
    inert (spam_filter._build_learned_lines skips a refinement with no
    headline), so a blank rule is refused rather than written."""
    desc = (description or "").strip()
    if not desc:
        return None
    now = now_iso()
    record = {
        "id": refinement_id,
        "kind": "new_pattern",
        "verdict": "spam",
        "rule_class": "curate",
        "headline": desc,
        "rationale": "",
        "what_this_doesnt_cover": "",
        "confidence": "high",
        "evidence": [],
        "first_learned": now,
        "last_reinforced": now,
        "match_count": 0,
        "status": "active",
        "scope": scope,
        "source": AUTHORED_SOURCE,
    }
    if enforcement:
        record["enforcement"] = enforcement.get("enforcement", "ai")
        record["residual_text"] = enforcement.get("residual_text", desc)
        record["deterministic_entries"] = list(
            enforcement.get("deterministic_entries", []))
    return record


def create_authored_refinement(description: str, scope,
                               source: str = "dashboard",
                               enforcement: dict | None = None) -> dict | None:
    """Author a NEW unwanted-category curate rule and persist it (Batch C).

    Locked read-modify-write of signals.json: mint a fresh R- id, build the
    ACTIVE curate record, append, save, and log an "authored" event. When
    ``enforcement`` carries deterministic markers, they are ALSO written to
    blacklist.json (tagged with this rule's id + scope) so the keyword/sender
    gates enforce them before the AI runs. The rule is in effect on the next
    filter tick (both sidecars are reloaded per run). Returns the saved record,
    or None if ``description`` was blank (nothing written)."""
    if not (description or "").strip():
        return None
    with file_lock.locked(paths.SIGNALS_PATH):
        data = load_signals()
        rid = _mint_refinement_id(data)
        record = build_authored_curate_refinement(rid, description, scope,
                                                  enforcement)
        data.setdefault("ai_refinements", []).append(record)
        save_signals(data)
    append_refinement_log({
        "ts": now_iso(),
        "event": "authored",
        "id": rid,
        "headline": record["headline"],
        "source": source,
    })
    # Sequential (not nested) lock: the blacklist write takes its own lock after
    # the signals lock is released, so there is no cross-file lock-ordering risk.
    if enforcement and enforcement.get("deterministic_entries"):
        write_provenance_entries(enforcement["deterministic_entries"], scope, rid)
    return record


def list_authored_refinements() -> list[dict]:
    """Every owner-authored curate rule (source==AUTHORED_SOURCE), whether
    ACTIVE or disabled (status "retired"), newest first — the data behind the
    Unwanted Categories editor. Unlike list_active_refinements, status is NOT
    filtered, because the editor shows disabled rules too (with a toggle to
    re-enable)."""
    rows = [r for r in load_signals().get("ai_refinements", [])
            if r.get("source") == AUTHORED_SOURCE]
    rows.sort(key=lambda r: r.get("first_learned", ""), reverse=True)
    return rows


def retire_refinement(refinement_id: str, source: str = "dashboard") -> bool:
    """Config_io twin of spam_filter.retire_ai_refinement — MUST stay in sync
    with it (the two trees never import each other, so the semantics are
    duplicated; the engine body is the source of truth). DISABLE a rule: flip
    its ai_refinement status from "active" to "retired" (never delete —
    reversible; restore_refinement, the unretire twin, flips it back). Excludes
    it from prompt injection on the next filter tick. Returns True if a matching
    ACTIVE rule was retired, False if missing / already inactive (idempotent —
    safe on repeated clicks). Used by the Unwanted Categories editor's
    enable/disable toggle."""
    retired = False
    was_authored = False
    with file_lock.locked(paths.SIGNALS_PATH):
        data = load_signals()
        for r in data.get("ai_refinements", []) or []:
            if r.get("id") == refinement_id \
                    and r.get("status", "active") == "active":
                r["status"] = "retired"
                r["retired_at"] = now_iso()
                retired = True
                was_authored = r.get("source") == AUTHORED_SOURCE
                break
        if retired:
            save_signals(data)
    if retired:
        append_refinement_log({
            "ts": now_iso(),
            "event": "retired_by_owner",
            "id": refinement_id,
            "source": source,
        })
        # Cascade: disabling an authored rule must also stop its deterministic
        # gate hits, so remove its provenance-tagged blacklist entries (restore
        # re-adds them). Hand-added blocks are untouched.
        if was_authored:
            remove_provenance_entries(refinement_id)
    return retired


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

        # Add to active list. Finding #8: the id may reference a rule the owner
        # DROPped. Approving does not un-drop it, so distinguish a genuine new
        # rule from an already-active one (no-op) from a RETIRED one that this
        # apply cannot reactivate (honest fail — the owner must RESTORE it).
        data = load_signals()
        refinements = data.setdefault("ai_refinements", [])
        rid = refinement.get("id")
        existing = next((r for r in refinements if r.get("id") == rid),
                        None) if rid else None
        if existing is not None and existing.get("status", "active") != "active":
            outcome = "retired"
        elif existing is not None:
            # Already active — treat as no-op but still mark conv resolved.
            outcome = "already_active"
        else:
            outcome = "applied"
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

        if outcome != "retired":
            # Retired: leave the proposal PENDING (do not resolve it) so the
            # Dashboard can ack honestly and point the owner at the email
            # RESTORE reply.
            conv["status"] = "approved"
            conv["resolution"] = "approved"
            conv.setdefault("conversation_history", []).append({
                "role": "system",
                "timestamp": now_iso(),
                "content": f"Approved via {source}",
            })
            save_pending_signals(pending)
    # Log ONLY a genuine append as "applied" (re-approving an already-active
    # rule must not double-log). A retired-id approval is a no-op → "apply_failed".
    if outcome == "applied":
        append_refinement_log({
            "ts": now_iso(),
            "event": "applied",
            "id": refinement.get("id"),
            "sfid": sfid,
            "headline": refinement.get("headline", ""),
            "source": source,
        })
        return refinement
    if outcome == "retired":
        append_refinement_log({
            "ts": now_iso(),
            "event": "apply_failed",
            "id": rid,
            "sfid": sfid,
            "reason": "referenced rule is retired",
            "source": source,
        })
        return {"id": rid, "status": "retired",
                "headline": refinement.get("headline", "")}
    # already_active: truthful "it's active" for the caller; no re-log.
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


# ---------------------------------------------------------------------------
# False-positive narrowing helpers — DUPLICATED from spam_filter.py.
#
# config_io (the GUI package) and the engine (payload/MailWarden/src) are two
# packages that never import each other — they share JSON sidecars only — so the
# small PURE FP helpers the Dashboard "Approve" needs are copied here verbatim
# rather than imported. They MUST stay byte-identical to their spam_filter.py
# originals; a drift-guard test (tests/test_fp_dashboard_approve.py) feeds one
# fixture to both parsers and asserts identical output. If you edit one copy,
# edit the other. Keeping spam_filter.py untouched also keeps the offline eval
# byte-identical to baseline.
#
# Mirrors spam_filter.py: _FP_SECTION_LABELS / _FP_LABEL_* (~3444),
# _normalize_fp_analysis (~3466), _parse_fp_proposed_changes (~3482),
# _fp_changes_appliable (~3500), _mint_refinement_id (~3339),
# _fp_narrowing_headline (~3330), _fp_narrowing_to_refinement (~3352).
# ---------------------------------------------------------------------------

_FP_SECTION_LABELS = (
    "WHY IT WAS FLAGGED", "WHY THE USER IS RIGHT",
    "PROPOSED CHANGE", "TRADEOFF", "MY RECOMMENDATION",
)
_FP_LABEL_ALT = "|".join(re.escape(x) for x in _FP_SECTION_LABELS)
# A label line WITH a colon; leading heading hashes and/or bold markers are
# tolerated, and inline content may follow ("**TRADEOFF:** low risk"). The
# colon may sit inside the bold span ("**LABEL:**") or outside ("**LABEL**:").
_FP_LABEL_COLON = re.compile(
    r'^[ \t]*#{0,6}[ \t]*(?:\*\*|__)?[ \t]*'
    r'(?P<label>' + _FP_LABEL_ALT + r')'
    r'[ \t]*(?::[ \t]*(?:\*\*|__)?|(?:\*\*|__)[ \t]*:)'
    r'[ \t]*(?P<rest>.*?)[ \t]*$')
# A Markdown HEADING label with no colon ("## PROPOSED CHANGE") — the label
# must be the entire line, and at least one '#' is required so plain prose
# ("PROPOSED CHANGE ideas …") is never mistaken for a section boundary.
_FP_LABEL_BARE = re.compile(
    r'^[ \t]*#{1,6}[ \t]*(?:\*\*|__)?[ \t]*'
    r'(?P<label>' + _FP_LABEL_ALT + r')'
    r'[ \t]*(?:\*\*|__)?[ \t]*$')


def _normalize_fp_analysis(analysis: str) -> str:
    """Rewrite Markdown-dressed FP section labels to bare 'LABEL:' lines so the
    strict capture below can find them. Non-label lines pass through verbatim."""
    out = []
    for line in analysis.split("\n"):
        m = _FP_LABEL_COLON.match(line) or _FP_LABEL_BARE.match(line)
        if m:
            rest = (m.groupdict().get("rest") or "").strip()
            out.append(m.group("label") + ":")
            if rest:
                out.append(rest)
        else:
            out.append(line)
    return "\n".join(out)


def _parse_fp_proposed_changes(analysis: str) -> dict:
    """Extract PROPOSED CHANGE / TRADEOFF from an FP analysis, tolerating
    Markdown heading/bold dressing on the labels. Preserves the original
    capture contract: PROPOSED CHANGE is bounded by TRADEOFF, and TRADEOFF by
    MY RECOMMENDATION."""
    proposed = {"signals_to_narrow": {}, "tradeoffs": ""}
    norm = _normalize_fp_analysis(analysis or "")
    prop_match = re.search(
        r'(?ms)^PROPOSED CHANGE:\s*\n(.*?)(?=^TRADEOFF:$)', norm)
    trade_match = re.search(
        r'(?ms)^TRADEOFF:\s*\n(.*?)(?=^MY RECOMMENDATION:$)', norm)
    if prop_match:
        proposed["signals_to_narrow"]["from_analysis"] = prop_match.group(1).strip()
    if trade_match:
        proposed["tradeoffs"] = trade_match.group(1).strip()
    return proposed


def _fp_changes_appliable(proposed_changes: dict) -> bool:
    """True when a parsed FP proposal carries at least one non-blank narrowing."""
    narrowings = (proposed_changes or {}).get("signals_to_narrow") or {}
    return any(str(v).strip() for v in narrowings.values())


def _mint_refinement_id(signals: dict) -> str:
    """Mint an R-YYYYMMDD-<token> id unique against this signals dict's
    ai_refinements. Same format as spam_filter._mint_refinement_id /
    utils.random_token (secrets.token_hex(6)); no pending read, so it is safe
    to call while already holding the SIGNALS_PATH lock."""
    existing = {r.get("id", "") for r in (signals.get("ai_refinements") or [])}
    today = datetime.now().strftime("%Y%m%d")
    while True:
        rid = f"R-{today}-{secrets.token_hex(6)}"
        if rid not in existing:
            return rid


def _fp_refinement_id(conv: dict, signals: dict) -> str:
    """Deterministic R- id for an FP-narrowing approval (finding 3). Twin of
    spam_filter._fp_refinement_id.

    Both approval channels (Dashboard Approve + email YES) run the same conv
    through this, so they mint the SAME id for one proposal — the apply-time
    dedup then turns a second apply into a no-op (already_active) instead of a
    duplicate rule. The SFID is 'SFID-YYYYMMDD-<token>' and unique per proposal,
    so 'R-YYYYMMDD-<token>' (its tail re-prefixed) is unique too and keeps the
    _mint_refinement_id format. Falls back to a random unique id only when no
    SFID is present."""
    sfid = (conv.get("id") or "").strip()
    if sfid.startswith("SFID-") and len(sfid) > len("SFID-"):
        return "R-" + sfid[len("SFID-"):]
    return _mint_refinement_id(signals)


def _fp_narrowing_headline(proposed_changes: dict) -> str:
    """Join the non-blank narrowing texts of a parsed FP proposal into one
    plain-English headline (in practice a single 'from_analysis' entry)."""
    narrowings = (proposed_changes or {}).get("signals_to_narrow") or {}
    parts = [str(v).strip() for v in narrowings.values() if str(v).strip()]
    return "\n".join(parts)


def _fp_narrowing_to_refinement(proposed_changes: dict, conv: dict,
                                signals: dict, *, source: str) -> dict:
    """Build a LEGITIMATE ai_refinement record from an approved FP narrowing.

    verdict 'legitimate' so the classifier renders it as a NOT_SPAM exclusion;
    scope 'all' so it keeps the global reach the legacy soft_signals narrowing
    had; a real R- id so it is visible/deletable in the Dashboard. PURE (no IO).

    Finding 3: the id is DETERMINISTIC — derived from the proposal's SFID — so
    the Dashboard-Approve and email-YES channels mint the SAME id and a second
    apply dedupes instead of creating a duplicate rule. ``signals`` is used only
    for the fallback random id when no SFID is present."""
    now = now_iso()
    subject = (conv.get("original_subject") or "").strip()
    return {
        "id": _fp_refinement_id(conv, signals),
        "kind": "fp_narrowing",
        "verdict": "legitimate",
        "rule_class": None,
        "headline": _fp_narrowing_headline(proposed_changes),
        "rationale": (proposed_changes.get("tradeoffs") or "").strip(),
        "what_this_doesnt_cover": "",
        "confidence": "medium",
        "evidence": [subject or "false-positive-forward"],
        "first_learned": now,
        "last_reinforced": now,
        "match_count": 1,
        "status": "active",
        "scope": "all",
        "source": source,
    }


def apply_fp_narrowing_from_pending(sfid: str,
                                    source: str = "dashboard") -> dict | None:
    """Approve a pending false_positive narrowing from the Dashboard (Feature 1).

    Mirrors the engine's email-YES false_positive arm in spam_filter.run_filter
    and the spam-example twin apply_refinement_from_pending: verify-before-ack +
    self-heal, then route the approved narrowing through the MODERN refinements
    store (a LEGITIMATE, scope-"all" ai_refinement with a real R- id) and run the
    same applied / already_active / retired state logic — so a Dashboard approval
    lands in the identical state an email YES would.

    Returns:
      {"status": "applied"|"already_active"|"retired", "id": rid, "headline": h}
      {"status": "no_change"}  — the proposal carried no readable change (the
                                 self-heal re-parse also failed): NOTHING written,
                                 conv left PENDING, logged "apply_failed".
      None                     — sfid not found / not awaiting_reply / not a
                                 false_positive proposal.
    """
    # ONE lock over BOTH sidecars for the whole op (C7). file_lock.locked sorts
    # the pair into a fixed order internally, so this can never deadlock against
    # another op taking the same pair in the opposite order. Fresh reads under
    # the lock mean a concurrent learner save / parallel approval isn't clobbered.
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
        # FP conversations predate the "kind" field, so the default matches the
        # engine's own conv.get("kind", "false_positive").
        if conv.get("kind", "false_positive") != "false_positive":
            return None

        # Verify-before-ack + self-heal (mirrors spam_filter's legacy-FP arm):
        # an older parser may have stored an EMPTY proposed_changes for a
        # Markdown-dressed analysis. Re-parse api_analysis with the tolerant
        # parser and persist the healed changes before deciding.
        proposed = conv.get("proposed_changes") or {}
        if not _fp_changes_appliable(proposed):
            proposed = _parse_fp_proposed_changes(conv.get("api_analysis", ""))
            if _fp_changes_appliable(proposed):
                conv["proposed_changes"] = proposed
        if not _fp_changes_appliable(proposed):
            # Nothing appliable: do NOT approve, do NOT write signals, leave the
            # conv PENDING; record the honest no-op (never "applied").
            append_refinement_log({
                "ts": now_iso(),
                "event": "apply_failed",
                "sfid": sfid,
                "reason": "analysis contained no readable proposed change",
                "source": source,
            })
            return {"status": "no_change"}

        # Build the modern refinement (fresh R- id) and run the same 3-way
        # applied / already_active / retired logic as apply_refinement_from_pending.
        data = load_signals()
        refinements = data.setdefault("ai_refinements", [])
        refinement = _fp_narrowing_to_refinement(proposed, conv, data,
                                                 source=source)
        rid = refinement.get("id")
        existing = next((r for r in refinements if r.get("id") == rid),
                        None) if rid else None
        if existing is not None and existing.get("status", "active") != "active":
            outcome = "retired"
        elif existing is not None:
            outcome = "already_active"
        else:
            outcome = "applied"
            refinements.append(refinement)
            save_signals(data)

        if outcome != "retired":
            # applied / already_active: resolve the conv (any self-heal write is
            # persisted with it). "retired" leaves the conv PENDING so the owner
            # can act on the honest ack.
            conv["status"] = "approved"
            conv["resolution"] = "approved"
            conv.setdefault("conversation_history", []).append({
                "role": "system",
                "timestamp": now_iso(),
                "content": f"Approved via {source}",
            })
            save_pending_signals(pending)
    # Log ONLY a genuine append as "applied" (an already-active re-approval must
    # not double-log; a retired-id approval is a no-op → "apply_failed").
    if outcome == "applied":
        append_refinement_log({
            "ts": now_iso(),
            "event": "applied",
            "id": rid,
            "sfid": sfid,
            "headline": refinement.get("headline", ""),
            "source": source,
        })
        return {"status": "applied", "id": rid,
                "headline": refinement.get("headline", "")}
    if outcome == "retired":
        append_refinement_log({
            "ts": now_iso(),
            "event": "apply_failed",
            "id": rid,
            "sfid": sfid,
            "reason": "referenced rule is retired",
            "source": source,
        })
        return {"status": "retired", "id": rid,
                "headline": refinement.get("headline", "")}
    # already_active: truthful "it's active" for the caller; no re-log.
    return {"status": "already_active", "id": rid,
            "headline": refinement.get("headline", "")}


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

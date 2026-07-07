#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Daily Report — Sends a summary email of the last 24 hours of spam filter activity.
Also serves as a system heartbeat: if the email stops arriving, something is wrong.
"""

import email
import email.header
import email.policy
import json
import logging
import os
import re
import smtplib
import sys
import tempfile
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from pathlib import Path

import file_lock

from utils import parse_from_address, extract_domain, random_token

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "config.json"
DECISIONS_LOG_PATH = PROJECT_ROOT / "memory" / "decisions.log"
SIGNALS_PATH = PROJECT_ROOT / "memory" / "signals.json"
WHITELIST_PATH = PROJECT_ROOT / "memory" / "whitelist.json"
BLACKLIST_PATH = PROJECT_ROOT / "memory" / "blacklist.json"
TOKEN_USAGE_PATH = PROJECT_ROOT / "memory" / "token_usage.json"
REPORT_STATE_PATH = PROJECT_ROOT / "memory" / "report_state.json"
# Token-keyed number->sender maps for report APPROVE replies (safe
# sender-approval feature). Written here at report-send time; spam_filter.py
# reads it when the owner replies "APPROVE <n>" to a [MWR-<token>] report.
REPORT_APPROVALS_PATH = PROJECT_ROOT / "memory" / "report_approvals.json"
# Report-approval tokens expire after this many days (locked product decision).
REPORT_APPROVAL_MAX_AGE_DAYS = 30
# item (b): FP-driven learned-rule review queue (rule-id keyed). Written by the
# filter (enqueue on an APPROVE rescue driven by a learned R- rule; KEEP/DROP
# resolve). Read here to render the LEARNED-RULE REVIEW section; pending entries
# auto-expire (silent "kept") after RULE_REVIEW_MAX_AGE_DAYS.
RULE_REVIEWS_PATH = PROJECT_ROOT / "memory" / "rule_reviews.json"
RULE_REVIEW_MAX_AGE_DAYS = 30
REPORT_BOUNDARY_HOUR = 8  # local clock hour the report "day" rolls over
PENDING_SIGNALS_PATH = PROJECT_ROOT / "memory" / "pending_signals.json"
# Persistent lifetime counters that survive pruning of decisions.log and
# pending_signals.json (written by spam_filter's prune helpers). The report
# adds these to its per-run signal-history totals so they never reset.
LIFETIME_STATS_PATH = PROJECT_ROOT / "memory" / "lifetime_stats.json"
# The learner now stores its scan watermark here (audit L3) instead of in
# config.json; the report reads it for the "Last ran" line, falling back to the
# legacy config value for installs that predate the change.
LEARNER_STATE_PATH = PROJECT_ROOT / "memory" / "learner_state.json"
# Append-only refinement-event log the Dashboard's Signal History renders. The
# report is one of four independent appenders (the others live in spam_filter,
# learn_signals, and config_io); it records an "expired" event when a pending
# proposal times out (finding #16) so the history is not perpetually empty.
REFINEMENTS_LOG_PATH = PROJECT_ROOT / "memory" / "signal_refinements.log"
LOG_PATH = PROJECT_ROOT / "logs" / "spam_filter.log"


def get_whitelist_dir(config: dict) -> Path:
    """Get the whitelist folder path from config, with fallback."""
    wl_config = config.get("whitelist", {})
    folder = wl_config.get("folder", "")
    if folder:
        return Path(folder)
    return PROJECT_ROOT / "whitelist"


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("daily_report")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(handler)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(stdout_handler)

    return logger


def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


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
    try:
        with open(SIGNALS_PATH, "r") as f:
            return scrub_retired_signals(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _list_entry_value(entry) -> str:
    """Read the value from a whitelist/blacklist entry that may be a plain
    string (legacy/hand-typed) OR an object — ``{"value": <addr>, "provenance":
    "approve"}`` for an APPROVE-sourced whitelist address, or ``{"value","scope"}``
    for a scoped block-list entry (audit 2026-07-06). Engine twin of
    spam_filter._whitelist_addr_value; kept local so daily_report imports no
    engine module. READ-ONLY tolerance — used only for set-build/compare, never
    on a write path, so the stored shape is preserved. The RAW string is returned
    (callers apply their own casing) and a malformed entry yields ""."""
    v = entry.get("value") if isinstance(entry, dict) else entry
    return v if isinstance(v, str) else ""


def load_whitelist() -> dict:
    try:
        with open(WHITELIST_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "version": "1.0",
            "last_updated": "",
            "notes": "Managed automatically.",
            "addresses": [],
            "domains": [],
        }


def save_whitelist(data: dict):
    """Atomic write of whitelist.json."""
    data["last_updated"] = datetime.now().isoformat()
    fd, tmp_path = tempfile.mkstemp(dir=WHITELIST_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, WHITELIST_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def process_whitelist_emls(whitelist_dir: Path, logger: logging.Logger) -> list:
    """Process .eml files in the whitelist/ folder.

    Extracts From: addresses, adds to whitelist.json, deletes the .eml files.
    Returns a list of dicts describing what was added.
    """
    additions = []
    # Locked read-modify-write of whitelist.json so the filter's command
    # handlers / Dashboard edits can't be clobbered by this folder sync (C7).
    # The load is fresh-under-lock and the save stays inside the same hold.
    with file_lock.locked(WHITELIST_PATH):
        whitelist = load_whitelist()
        existing = {v.lower() for v in (_list_entry_value(a)
                    for a in whitelist.get("addresses", [])) if v}

        if not whitelist_dir.is_dir():
            logger.warning(f"[WHITELIST] Folder does not exist: {whitelist_dir}")
            return additions

        eml_files = sorted(whitelist_dir.glob("*.eml"))
        if not eml_files:
            return additions

        changed = False
        for eml_path in eml_files:
            try:
                with open(eml_path, "rb") as f:
                    msg = email.message_from_binary_file(f, policy=email.policy.compat32)

                from_header = msg.get("From", "")
                parsed = parse_from_address(from_header)
                addr = parsed.get("address")

                if addr is None:
                    logger.error(
                        f"[WHITELIST] Failed to parse From: header in {eml_path.name} "
                        f"— raw header: {from_header!r}. File left for investigation."
                    )
                    continue

                subject = msg.get("Subject", "(no subject)")
                # Decode subject if needed
                try:
                    decoded_parts = email.header.decode_header(subject)
                    subject_parts = []
                    for part, charset in decoded_parts:
                        if isinstance(part, bytes):
                            subject_parts.append(part.decode(charset or "utf-8", errors="replace"))
                        else:
                            subject_parts.append(part)
                    subject = " ".join(subject_parts)
                except Exception:
                    pass

                if addr in existing:
                    logger.info(
                        f"[WHITELIST] Address already present: {addr} "
                        f"(from: {eml_path.name}). Deleting .eml."
                    )
                    eml_path.unlink()
                    continue

                whitelist.setdefault("addresses", []).append(addr)
                existing.add(addr)
                changed = True

                logger.info(
                    f"[WHITELIST] Added address: {addr} "
                    f"(from: {from_header}, subject: {subject})"
                )
                additions.append({
                    "address": addr,
                    "from_header": from_header,
                    "subject": subject,
                })

                # Delete the .eml after successful processing
                eml_path.unlink()

            except Exception as e:
                logger.error(
                    f"[WHITELIST] Error processing {eml_path.name}: {e}. "
                    f"File left for investigation."
                )

        if changed:
            save_whitelist(whitelist)

    return additions


def sync_domains_txt(whitelist_dir: Path, logger: logging.Logger) -> dict:
    """Sync domains.txt to whitelist.json.

    Returns dict with 'added', 'removed' lists and 'total' count.
    """
    result = {"added": [], "removed": [], "total": 0}
    domains_txt_path = whitelist_dir / "domains.txt"

    # Read domains.txt
    new_domains = []
    if domains_txt_path.exists():
        try:
            with open(domains_txt_path, "r") as f:
                for line in f:
                    line = line.strip()
                    # Handle \r\n line endings
                    line = line.rstrip("\r")
                    if not line or line.startswith("#"):
                        continue
                    # Normalize: lowercase, ensure @ prefix
                    domain = line.lower().strip()
                    if not domain.startswith("@"):
                        domain = "@" + domain
                    new_domains.append(domain)
        except Exception as e:
            logger.error(f"[WHITELIST] Failed to read domains.txt: {e}")
            return result
    else:
        logger.warning("[WHITELIST] domains.txt not found")

    # Locked read-modify-write of whitelist.json so a concurrent filter command
    # handler / Dashboard edit is not clobbered by this domains.txt sync (C7).
    with file_lock.locked(WHITELIST_PATH):
        whitelist = load_whitelist()
        old_domains = {v.lower() for v in (_list_entry_value(d)
                       for d in whitelist.get("domains", [])) if v}
        new_domains_set = set(new_domains)

        result["added"] = sorted(new_domains_set - old_domains)
        result["removed"] = sorted(old_domains - new_domains_set)
        result["total"] = len(new_domains_set)

        if result["added"] or result["removed"]:
            whitelist["domains"] = sorted(new_domains_set)
            save_whitelist(whitelist)
            for d in result["added"]:
                logger.info(f"[WHITELIST] Domain added: {d}")
            for d in result["removed"]:
                logger.info(f"[WHITELIST] Domain removed: {d}")
        else:
            logger.info(f"[WHITELIST] Domain list unchanged ({result['total']} domains)")

    return result


def load_blacklist() -> dict:
    try:
        with open(BLACKLIST_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "version": "1.0",
            "last_updated": "",
            "notes": "Managed automatically.",
            "addresses": [],
            "display_names": [],
        }


def save_blacklist(data: dict):
    data["last_updated"] = datetime.now().isoformat()
    fd, tmp_path = tempfile.mkstemp(dir=BLACKLIST_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, BLACKLIST_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def load_skip_names(blacklist_dir: Path) -> set:
    """Load skip_names.txt as a lowercased set."""
    path = blacklist_dir / "skip_names.txt"
    if not path.exists():
        return set()
    names = set()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip().rstrip("\r")
                if not line or line.startswith("#"):
                    continue
                names.add(line.lower())
    except Exception:
        pass
    return names


def most_recent_boundary(now: datetime) -> datetime:
    """Latest local 08:00 boundary at or before `now`. Calendar arithmetic on
    naive local datetimes, so a 23h/25h DST day still maps to that date's 08:00."""
    boundary_today = now.replace(hour=REPORT_BOUNDARY_HOUR, minute=0,
                                 second=0, microsecond=0)
    if now >= boundary_today:
        return boundary_today
    return boundary_today - timedelta(days=1)


def compute_report_window(now: datetime, last_report_through):
    """Return (start, end) for one report run. end = most recent 08:00 boundary.
    start = the watermark, or (first run / None) the prior 08:00 boundary (one
    complete day). Clamped so start <= end (a clock rewind yields an empty
    window, never a negative one)."""
    end = most_recent_boundary(now)
    if last_report_through is None:
        start = end - timedelta(days=1)
    else:
        start = last_report_through
        if start > end:
            start = end
    return start, end


def load_report_state() -> dict:
    """Read report_state.json. Caller holds the lock (mirrors load_token_usage)."""
    try:
        with open(REPORT_STATE_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_report_state(data: dict):
    """Atomic write of report_state.json. Caller holds the lock (mirrors save_token_usage)."""
    fd, tmp_path = tempfile.mkstemp(dir=REPORT_STATE_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, REPORT_STATE_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def load_report_approvals() -> dict:
    """Read report_approvals.json. Caller holds the lock (mirrors load_report_state)."""
    try:
        with open(REPORT_APPROVALS_PATH, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_report_approvals(data: dict):
    """Atomic write of report_approvals.json. Caller holds the lock (mirrors save_report_state)."""
    fd, tmp_path = tempfile.mkstemp(dir=REPORT_APPROVALS_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, REPORT_APPROVALS_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def numbered_spam_entries(decisions: dict) -> list:
    """The report's junked-mail entries in their RENDERED numbering order:
    one unified 1..k space, moved entries first, then dry-run entries —
    exactly the order build_report_body renders them."""
    moved = [e for e in decisions.get("spam_entries", []) if not e.get("dry_run")]
    dry = [e for e in decisions.get("spam_entries", []) if e.get("dry_run")]
    return moved + dry


def build_approval_entries(decisions: dict) -> dict:
    """Number->sender map for one report's APPROVE tokens: {"1": {from_domain,
    from, subject}, ...} keyed by the SAME numbers the report body renders."""
    entries = {}
    for i, e in enumerate(numbered_spam_entries(decisions), 1):
        addr = parse_from_address(e.get("from", "")).get("address") or ""
        entries[str(i)] = {
            "from_domain": (extract_domain(addr) or "").lstrip("@"),
            "from": e.get("from", ""),
            "subject": e.get("subject", ""),
            # item (b): the learned rules that drove this junk verdict, so an
            # APPROVE rescue can queue them for review without re-scanning
            # decisions.log.
            "rule_ids": e.get("rule_ids", []),
            # Finding #6: what junked it, so the APPROVE handler can pick the
            # honest path per block type. Absent in pre-#6 token records; the
            # handler defaults those to "ai" (prior behavior).
            "block_source": e.get("block_source", "ai"),
        }
    return entries


def record_report_approvals(token: str, account: str, window_end,
                            entries: dict, logger: logging.Logger,
                            rule_reviews: dict = None):
    """Write one report's number->sender map under its [MWR-<token>] key.
    Tokens older than REPORT_APPROVAL_MAX_AGE_DAYS are pruned opportunistically
    inside the same locked write. Best-effort: a failure here must never block
    a report send."""
    try:
        with file_lock.locked(REPORT_APPROVALS_PATH):
            data = load_report_approvals()
            cutoff = datetime.now() - timedelta(days=REPORT_APPROVAL_MAX_AGE_DAYS)
            for tok in list(data.keys()):
                rec = data.get(tok)
                try:
                    created = datetime.fromisoformat(
                        (rec or {}).get("created", ""))
                    if created < cutoff:
                        del data[tok]
                except (ValueError, TypeError, AttributeError):
                    del data[tok]  # malformed record -> drop
            data[token] = {
                "created": datetime.now().isoformat(),
                "account": account,
                "window_end": window_end.isoformat(),
                "entries": entries,
                # item (b): number->rule-id map for KEEP/DROP replies under the
                # SAME token (verb disambiguates from APPROVE's entries).
                "rule_reviews": rule_reviews or {},
            }
            save_report_approvals(data)
    except Exception as e:
        logger.error(f"Failed to record report approvals for [MWR-{token}]: {e}")


# ---------------------------------------------------------------------------
# item (b): FP-driven learned-rule review — queue read + render
# ---------------------------------------------------------------------------

def load_rule_reviews() -> dict:
    """Read rule_reviews.json (rule-id-keyed pending review queue). Caller holds
    the lock (mirrors load_report_approvals)."""
    try:
        with open(RULE_REVIEWS_PATH, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_rule_reviews(data: dict):
    """Atomic write of rule_reviews.json. Caller holds the lock (mirrors
    save_report_approvals)."""
    fd, tmp_path = tempfile.mkstemp(dir=RULE_REVIEWS_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, RULE_REVIEWS_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def prune_rule_reviews(logger: logging.Logger) -> dict:
    """Locked load of the review queue, dropping entries older than
    RULE_REVIEW_MAX_AGE_DAYS (by ``first_queued``) — an unanswered review
    silently auto-resolves to "kept". Malformed entries are dropped. Returns the
    current (pruned) queue dict. Best-effort: never blocks a report."""
    try:
        with file_lock.locked(RULE_REVIEWS_PATH):
            data = load_rule_reviews()
            cutoff = datetime.now() - timedelta(days=RULE_REVIEW_MAX_AGE_DAYS)
            changed = False
            for rid in list(data.keys()):
                rec = data.get(rid)
                try:
                    fq = datetime.fromisoformat((rec or {}).get("first_queued", ""))
                    if fq < cutoff:
                        del data[rid]
                        changed = True
                except (ValueError, TypeError, AttributeError):
                    del data[rid]
                    changed = True
            if changed:
                save_rule_reviews(data)
            return data
    except Exception as e:
        logger.error(f"Failed to prune rule_reviews.json: {e}")
        return load_rule_reviews()


def _active_refinement_by_id(signals_data: dict, rid: str) -> dict:
    """Return the ACTIVE ai_refinement with id ``rid``, else None."""
    for r in (signals_data or {}).get("ai_refinements", []) or []:
        if r.get("id") == rid and r.get("status", "active") == "active":
            return r
    return None


def ordered_rule_reviews(queue: dict, signals_data: dict) -> list:
    """Deterministic, render-ready list of pending reviews whose rule is still
    an ACTIVE learned refinement (auto-dropping any that were already retired /
    removed — this is how the section stays honest without a write). Ordered by
    ``first_queued`` then rule id. Live rule metadata (headline/confidence/blind
    spot) is read fresh from signals_data; the queue snapshot is the fallback."""
    out = []
    for rid, rec in (queue or {}).items():
        ref = _active_refinement_by_id(signals_data, rid)
        if ref is None:
            continue
        rec = rec or {}
        out.append({
            "rule_id": rid,
            "headline": (ref.get("headline") or rec.get("headline") or "").strip(),
            "confidence": (ref.get("confidence") or rec.get("confidence")
                           or "medium"),
            "what_this_doesnt_cover": (
                ref.get("what_this_doesnt_cover") or "").strip(),
            "evidence": rec.get("evidence", []) or [],
            "first_queued": rec.get("first_queued", ""),
        })
    out.sort(key=lambda d: (d["first_queued"], d["rule_id"]))
    return out


def build_rule_review_entries(ordered: list) -> dict:
    """Number->rule-id map for one report's KEEP/DROP token, keyed by the SAME
    numbers build_rule_review_section renders (1..m)."""
    return {str(i): d["rule_id"] for i, d in enumerate(ordered, 1)}


def build_rule_review_section(ordered: list) -> list:
    """LEARNED-RULE REVIEW section lines (owner-approved copy). Empty when there
    is nothing pending. Numbered independently (1..m); the KEEP/DROP verb
    disambiguates from the APPROVE spam-list numbering."""
    if not ordered:
        return []
    lines = ["", "LEARNED-RULE REVIEW",
             "A sender you rescued had been junked by a rule MailWarden taught "
             "itself.",
             "Review the rule that caused it:", ""]
    for i, d in enumerate(ordered, 1):
        lines.append(f'{i}. [{d["rule_id"]}] "{d["headline"]}"')
        lines.append(f'   Confidence when learned: {d["confidence"]}')
        if d["what_this_doesnt_cover"]:
            lines.append(f'   Known blind spot: {d["what_this_doesnt_cover"]}')
        ev = d["evidence"][0] if d["evidence"] else None
        if ev:
            lines.append(f'   Triggered the rescue of: "{ev.get("subject", "")}"'
                         f' from {ev.get("from", "")}')
    lines.append("")
    lines.append("To DROP a rule (stop using it), reply DROP and the item "
                 "number (example: DROP 1).")
    lines.append("To KEEP a rule, reply KEEP 1. No reply leaves your rules "
                 "unchanged.")
    lines.append("Changed your mind about a dropped rule? Reply RESTORE and "
                 "its number (example: RESTORE 1), or restore it in the "
                 "Dashboard under Signal History → Dropped rules.")
    return lines


def _parse_state_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def count_blacklisted_blocked_24h(window_start, window_end) -> tuple:
    """Count BLACKLISTED decisions and gather entries within an explicit window.
    Now takes an explicit (window_start, window_end) half-open window.
    Returns (count, entries_list)."""
    count = 0
    entries = []

    if not DECISIONS_LOG_PATH.exists():
        return 0, []

    try:
        with open(DECISIONS_LOG_PATH, "r") as f:
            content = f.read()
    except Exception:
        return 0, []

    for entry in content.split("  ---\n"):
        entry = entry.strip()
        if not entry:
            continue
        # Finding #6: anchored to the DECISION: line (like
        # _classify_block_source) so this section and the numbered junk list
        # partition the junked mail exactly — a subject merely containing
        # "BLACKLISTED" can't land an email in both.
        if not re.search(r'^\s*DECISION: BLACKLISTED\b', entry, re.MULTILINE):
            continue
        ts_match = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', entry)
        if not ts_match:
            continue
        try:
            ts = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if ts < window_start or ts >= window_end:
            continue

        count += 1
        from_match = re.search(r'^\s*FROM: (.+)', entry, re.MULTILINE)
        subj_match = re.search(r'^\s*SUBJECT: (.+)', entry, re.MULTILINE)
        # Extract match type/value from decision line
        dec_match = re.search(r'DECISION: BLACKLISTED \(matched (\w+)(?: name)?: "?([^")]+)"?\)', entry)

        entries.append({
            "time": ts.strftime("%I:%M %p").lstrip("0"),
            "from": from_match.group(1).strip() if from_match else "Unknown",
            "subject": subj_match.group(1).strip() if subj_match else "",
            "match_type": dec_match.group(1) if dec_match else "",
            "match_value": dec_match.group(2) if dec_match else "",
        })

    return count, entries


def count_whitelisted_passthrough_24h(window_start, window_end) -> int:
    """Count WHITELISTED decisions in decisions.log within an explicit window.
    Now takes an explicit (window_start, window_end) half-open window."""
    count = 0

    if not DECISIONS_LOG_PATH.exists():
        return 0

    try:
        with open(DECISIONS_LOG_PATH, "r") as f:
            content = f.read()
    except Exception:
        return 0

    for entry in content.split("  ---\n"):
        entry = entry.strip()
        if not entry:
            continue
        if "WHITELISTED" not in entry:
            continue
        ts_match = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', entry)
        if not ts_match:
            continue
        try:
            ts = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
            if window_start <= ts < window_end:
                count += 1
        except ValueError:
            continue

    return count


def load_token_usage() -> dict:
    try:
        with open(TOKEN_USAGE_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "version": "1.0", "last_updated": "",
            "lifetime_input_tokens": 0, "lifetime_output_tokens": 0,
            "lifetime_api_calls": 0, "daily_records": [],
        }


def prune_token_usage(data: dict) -> dict:
    """Remove daily records older than 90 days."""
    cutoff = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
    data["daily_records"] = [
        r for r in data.get("daily_records", []) if r.get("date", "") >= cutoff
    ]
    return data


def save_token_usage(data: dict):
    data["last_updated"] = datetime.now().isoformat()
    fd, tmp_path = tempfile.mkstemp(dir=TOKEN_USAGE_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, TOKEN_USAGE_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


# Known model IDs -> friendly display labels, for the API USAGE line below.
# No other reusable ID->label map exists in the codebase (dashboard.py's
# MODEL_CHOICES pairs labels with classify-mode *selections*, not a plain
# id->name lookup) so this is the single source of truth; extend it here if
# new model IDs ship. Falls back to the raw ID for anything not listed.
MODEL_DISPLAY_LABELS = {
    "claude-haiku-4-5-20251001": "Claude Haiku 4.5",
    "claude-sonnet-4-6": "Claude Sonnet 4.6",
}


def build_api_usage_section(config: dict) -> list:
    """Build the API USAGE section lines (model + console link, no dollar amounts).

    classify_mode "cascade" is the shipped default (config_io.py DEFAULT_CONFIG
    anthropic.classify_mode) and runs two models — screen_model judges every
    email, confirm_model re-checks anything the screen stage would junk — so
    the report names both stages instead of implying Haiku alone is deciding.
    "single" mode keeps naming the one configured model, as before."""
    anthropic_config = config.get("anthropic", {})
    classify_mode = anthropic_config.get("classify_mode", "cascade")
    if classify_mode == "cascade":
        screen_model = anthropic_config.get(
            "screen_model", "claude-haiku-4-5-20251001")
        confirm_model = anthropic_config.get(
            "confirm_model", "claude-sonnet-4-6")
        screen_label = MODEL_DISPLAY_LABELS.get(screen_model, screen_model)
        confirm_label = MODEL_DISPLAY_LABELS.get(confirm_model, confirm_model)
        model_label = f"{screen_label} (screen) + {confirm_label} (confirm)"
    else:
        raw_model = anthropic_config.get("model", "")
        if raw_model == "claude-haiku-4-5-20251001" or not raw_model:
            model_label = "Claude Haiku 4.5"
        else:
            model_label = raw_model

    lines = []
    lines.append("-" * 39)
    lines.append("API USAGE")
    lines.append(f"Model: {model_label}")
    lines.append("See and manage your costs anytime: https://console.anthropic.com/settings/usage")
    return lines


def _load_lifetime_stats() -> dict:
    """Read lifetime_stats.json, returning an all-zero default on missing/corrupt
    (audit Session 9B). These counters carry the tallies of pending-signal
    conversations that have been pruned away, so the report's signal-history
    totals don't reset when old conversations are retired."""
    default = {
        "version": "1.0",
        "decisions_evaluated_lifetime": 0,
        "decisions_spam_lifetime": 0,
        "signals_submitted_lifetime": 0,
        "signals_approved_lifetime": 0,
        "signals_rejected_lifetime": 0,
    }
    try:
        with open(LIFETIME_STATS_PATH, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default
    for k, v in default.items():
        data.setdefault(k, v)
    return data


def load_pending_signals() -> dict:
    try:
        with open(PENDING_SIGNALS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"version": "1.0", "conversations": []}


def save_pending_signals(data: dict):
    fd, tmp_path = tempfile.mkstemp(dir=PENDING_SIGNALS_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, PENDING_SIGNALS_PATH)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def append_refinement_log(event: dict) -> None:
    """Append one JSON record to signal_refinements.log (finding #16).

    Byte-identical to the appenders in learn_signals.py / spam_filter.py so the
    Dashboard's Signal History renders report-written events the same way."""
    REFINEMENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with REFINEMENTS_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def expire_pending_signals(logger: logging.Logger) -> dict:
    """Expire pending conversations past their expiry date.
    Returns dict with 'expired' list and 'active' list for the report."""
    now_iso = datetime.now().isoformat()
    result = {"expired": [], "active": []}
    # Locked read-modify-write of pending_signals.json so a concurrent learner
    # append or filter resolution isn't clobbered by this expiry pass (T5/C7).
    # Also lock lifetime_stats.json: it's read here for the totals and the
    # filter's prune helpers write it under the same pair (audit Session 9B).
    with file_lock.locked(PENDING_SIGNALS_PATH, LIFETIME_STATS_PATH):
        pending = load_pending_signals()
        lifetime = _load_lifetime_stats()
        changed = False

        for conv in pending.get("conversations", []):
            if conv.get("status") == "awaiting_reply":
                if now_iso > conv.get("expires", ""):
                    conv["status"] = "expired"
                    conv["resolution"] = "expired"
                    result["expired"].append(conv)
                    changed = True
                    logger.info(f"[SIGNAL] Expired: {conv.get('id')} — {conv.get('original_subject', '')[:40]}")
                else:
                    result["active"].append(conv)

        if changed:
            save_pending_signals(pending)

    # Finding #16: record each expiry to the refinement log so the Dashboard's
    # "Rejected / expired / withdrawn" history is populated. Written AFTER the
    # locked RMW (mirrors config_io's convention) — it touches a different file
    # than the locked pending/lifetime pair, so it never lengthens that hold.
    for conv in result["expired"]:
        _ref = conv.get("proposed_refinement") or {}
        append_refinement_log({
            "ts": datetime.now().isoformat(),
            "event": "expired",
            "id": _ref.get("id", ""),
            "sfid": conv.get("id", ""),
            "headline": _ref.get("headline", "") or conv.get("original_subject", ""),
            "source": "report",
        })

    # Gather lifetime stats. The per-run scalars count the conversations still
    # ON DISK; the persistent lifetime counters add back the conversations that
    # have since been pruned away, so the totals never regress (audit Session 9B).
    all_convs = pending.get("conversations", [])
    result["total_submitted"] = (
        len(all_convs) + lifetime["signals_submitted_lifetime"])
    result["total_approved"] = (
        sum(1 for c in all_convs if c.get("resolution") == "approved")
        + lifetime["signals_approved_lifetime"])
    result["total_rejected"] = (
        sum(1 for c in all_convs if c.get("resolution") == "rejected")
        + lifetime["signals_rejected_lifetime"])
    result["total_pending"] = len(result["active"])

    return result


def _pending_was_emailed(conv: dict) -> bool:
    """True when this pending proposal was delivered to the owner as an email, so
    "reply YES to the proposal email" is an honest instruction (finding #9).

    Emailed kinds:
      * false_positive           — the FP analysis email (SFID bracketed
        MID-subject). FP conversations carry no explicit "kind", so the default
        lands here.
      * spam_example_proposal WITH a non-empty forwarder — the forward-spam
        learner (learn_signals.handle_new_pattern) emails these and stamps the
        forwarding account. The Check-an-Email screen
        (learn_signals.propose_from_teaching) hardcodes forwarder="" and sends NO
        email, so an empty/absent forwarder is treated as Dashboard-only — the
        SAFE default (never tell the owner to reply to an email that may not
        exist; block_sender_proposal is handled by kind, so its own non-empty
        forwarder is irrelevant here).
    Dashboard-only kinds: check-screen spam_example_proposal, block_sender_proposal.
    """
    kind = conv.get("kind", "false_positive")
    if kind == "false_positive":
        return True
    if kind == "spam_example_proposal":
        return bool((conv.get("forwarder") or "").strip())
    return False


def build_pending_signals_section(sig_status: dict) -> list:
    """Build PENDING SIGNAL REVIEWS section lines. Returns empty if nothing to show."""
    lines = []

    if sig_status["expired"] or sig_status["active"]:
        lines.append("")
        lines.append("PENDING SIGNAL REVIEWS")

        for conv in sig_status["expired"]:
            lines.append(f"1 proposal expired without response and was discarded.")
            lines.append(f"  Original: {conv.get('original_subject', 'Unknown')}")
            # Kind-aware re-teach path (finding #9). "Fwd: False Positive" is
            # correct ONLY for a false positive; every other kind (spam-example
            # forward, check-screen proposals, block-sender) is re-taught from the
            # Check an Email screen. Never emit the FP re-forward line for a
            # non-FP kind — it would tell the owner to mark real spam legitimate.
            if conv.get("kind", "false_positive") == "false_positive":
                lines.append(f"  To revisit: forward the original email again with \"Fwd: False Positive\" subject.")
            else:
                lines.append(f"  To revisit: re-teach it from the Check an Email screen in the MailWarden Dashboard.")

        for conv in sig_status["active"]:
            expires = conv.get("expires", "")[:10]
            sfid = conv.get("id")
            lines.append(f"1 proposal awaiting your response (expires {expires}):")
            lines.append(f"  [{sfid}] — {conv.get('original_subject', 'Unknown')}")
            # Feature 1 made EVERY pending kind approvable in the Dashboard, so
            # lead with that now-universal path. Only add the email-reply option
            # when an email actually exists (emailed kinds); never point the owner
            # at a reply for a Dashboard-only proposal (finding #9).
            if _pending_was_emailed(conv):
                lines.append(f"  Approve it in the MailWarden Dashboard (Signal History -> Pending), or reply YES to the proposal email that has [{sfid}] in its subject line.")
            else:
                lines.append(f"  Approve it in the MailWarden Dashboard: Signal History -> Pending. (This one has no email to reply to.)")

    # Always show signal history if there have been any submissions
    if sig_status.get("total_submitted", 0) > 0:
        lines.append("")
        lines.append("SIGNAL HISTORY")
        lines.append(
            f"False positives submitted: {sig_status['total_submitted']}  |  "
            f"Changes applied: {sig_status['total_approved']}  |  "
            f"Rejected: {sig_status['total_rejected']}  |  "
            f"Pending: {sig_status['total_pending']}"
        )

    return lines


def get_last_filter_run(window_start, window_end) -> tuple:
    """Find the most recent filter run timestamp and error count from the operational log.
    Now takes an explicit (window_start, window_end) half-open window for the
    runs/errors counts. last_run stays ABSOLUTE (the most-recent run, ungated).
    Returns (datetime_or_None, runs_in_window, errors_in_window)."""
    if not LOG_PATH.exists():
        return None, 0, 0

    last_run = None
    runs_24h = 0
    errors_24h = 0

    try:
        with open(LOG_PATH, "r") as f:
            for line in f:
                ts_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if not ts_match:
                    continue
                try:
                    ts = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue

                if "Spam filter starting" in line:
                    last_run = ts
                    if window_start <= ts < window_end:
                        runs_24h += 1

                if window_start <= ts < window_end and "[ERROR]" in line:
                    errors_24h += 1
    except Exception:
        pass

    return last_run, runs_24h, errors_24h


# Feature 3 (owner decision "Option C"): human-readable name for each of the 4
# HARD pre-classifier tripwires. Mail these catch is junked with NO AI review, so
# the daily report flags it distinctly and names the tripwire — a rare mistake
# then jumps out and the owner can rescue the sender with APPROVE.
_TRIPWIRE_LABELS = {
    "SPF_DKIM_BOTH_FAIL": "failed both authentication checks",
    "LEAKED_AI_PROMPT": "hidden AI-prompt text in the message",
    "PROMPT_INJECTION_HARD": "a prompt-injection attempt in the message",
    "IP_DNSBL_MULTIPLE": "sending server listed on multiple spam blocklists",
}


def _tripwire_reason(signals: str) -> str:
    """Plain-English name(s) for the hard pre-classifier tripwire(s) a junking
    tripped, parsed from its SIGNALS HIT field. Falls back to the raw signal
    text for any unmapped signal so the flag line is never empty."""
    hit = [s.strip() for s in (signals or "").split(",") if s.strip()]
    named = [_TRIPWIRE_LABELS.get(s, s) for s in hit]
    return ", ".join(named)


def _classify_block_source(entry: str) -> str:
    """What junked this decisions.log entry: "blacklist", "subject_keyword",
    "pre_classifier", or "ai" (finding #6).

    Matches only MailWarden-emitted text on its own DECISION:/ACTION: lines
    (log_decision sanitizes newlines out of sender-controlled fields, so a
    subject can never start a line and forge a source). Order matters: the
    filter's precedence is blacklist, then subject-keyword, then the
    pre-classifier, then the AI."""
    if re.search(r'^\s*DECISION: BLACKLISTED\b', entry, re.MULTILINE):
        return "blacklist"
    if (re.search(r'^\s*DECISION: BLOCKED \(subject keyword', entry,
                  re.MULTILINE)
            or re.search(r'^\s*ACTION:.*\(subject-keyword\)', entry,
                         re.MULTILINE)):
        return "subject_keyword"
    if re.search(r'^\s*ACTION:.*\(pre-classifier\)', entry, re.MULTILINE):
        return "pre_classifier"
    return "ai"


def parse_decisions_24h(window_start, window_end) -> dict:
    """Parse decisions.log for entries within an explicit window.
    Now takes an explicit (window_start, window_end) half-open window."""
    result = {
        "evaluated": 0,
        "spam_moved": 0,
        "spam_dry_run": 0,
        "not_spam": 0,
        "errors": 0,
        "spam_entries": [],
        "per_account": {},
    }

    if not DECISIONS_LOG_PATH.exists():
        return result

    try:
        with open(DECISIONS_LOG_PATH, "r") as f:
            content = f.read()
    except Exception:
        return result

    entries = content.split("  ---\n")

    # Finding #12: exact-duplicate suppression for spam records. The pre-fix
    # dry-run filter re-classified (and re-logged) the same UNSEEN spam every
    # tick, so a legacy decisions.log can carry the same message dozens of
    # times inside one report window — each repeat used to become another
    # numbered junk entry with its own APPROVE token AND inflate the
    # spam/evaluated counters. Key is (message-id, dry-run-ness): exact
    # repeats collapse to one, while a dry-run preview record and a later
    # real MOVED record for the same message (the normal Dry Run -> real
    # transition) both remain visible. Same exactly-one discipline as the F1
    # history-index guard: a record with zero or more than one MESSAGE-ID
    # line is NON-DEDUPABLE and is counted exactly as before.
    seen_spam_keys = set()

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue

        ts_match = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', entry)
        if not ts_match:
            continue

        try:
            ts = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

        if ts < window_start or ts >= window_end:
            continue

        # Extract account name — timestamp and ACCOUNT: share the first line
        acct_match = re.search(r'ACCOUNT:\s*(.+)', entry)
        acct_name = acct_match.group(1).strip() if acct_match else "Unknown"

        # Initialize per-account counters
        if acct_name not in result["per_account"]:
            result["per_account"][acct_name] = {
                "evaluated": 0, "spam": 0, "spam_dry_run": 0, "not_spam": 0
            }

        result["evaluated"] += 1
        result["per_account"][acct_name]["evaluated"] += 1

        if "WHITELISTED" in entry:
            # Whitelisted entries are counted separately, not in evaluated/not_spam
            result["evaluated"] -= 1
            result["per_account"][acct_name]["evaluated"] -= 1
            continue

        if "DELETED" in entry and "spam_action=delete" in entry:
            # Detected as spam and permanently deleted (no Junk folder copy).
            result["spam_moved"] += 1
            result["per_account"][acct_name]["spam"] += 1
            result.setdefault("deleted", 0)
            result["deleted"] += 1
            continue

        if "MOVE FAILED" in entry:
            # Detected as spam, but IMAP move failed. Count as spam_moved
            # (it WAS classified as spam) plus separate move_failed for visibility.
            result["spam_moved"] += 1
            result["per_account"][acct_name]["spam"] += 1
            result.setdefault("move_failed", 0)
            result["move_failed"] += 1
            continue

        if "MOVED to" in entry or "would move to" in entry:
            # Finding #12 dedup (see seen_spam_keys above). Runs BEFORE the
            # counter increments so the counts and the numbered list stay
            # consistent; the evaluated decrement mirrors the WHITELISTED
            # idiom ("this record does not count").
            mid_matches = re.findall(r'^\s*MESSAGE-ID: (.+)', entry,
                                     re.MULTILINE)
            if len(mid_matches) == 1:
                dedup_key = (mid_matches[0].strip(),
                             "would move to" in entry)
                if dedup_key in seen_spam_keys:
                    result["evaluated"] -= 1
                    result["per_account"][acct_name]["evaluated"] -= 1
                    continue
                seen_spam_keys.add(dedup_key)

            if "MOVED to" in entry:
                result["spam_moved"] += 1
                result["per_account"][acct_name]["spam"] += 1
            elif "would move to" in entry:
                result["spam_dry_run"] = result.get("spam_dry_run", 0) + 1
                result["per_account"][acct_name]["spam_dry_run"] = (
                    result["per_account"][acct_name].get("spam_dry_run", 0) + 1)

            # Finding #6: blacklisted mail keeps its counter contribution
            # above but is NOT added to the numbered junk list — it already
            # renders (with its match type) in the BLACKLIST ACTIVITY section,
            # and an APPROVE on it could never work: the blacklist runs before
            # every approval mechanism.
            block_source = _classify_block_source(entry)
            if block_source == "blacklist":
                continue

            # Extract details for the spam list (anchored to line start)
            from_match = re.search(r'^\s*FROM: (.+)', entry, re.MULTILINE)
            subj_match = re.search(r'^\s*SUBJECT: (.+)', entry, re.MULTILINE)
            conf_match = re.search(r'confidence: ([\d.]+)', entry)
            sig_match = re.search(r'^\s*SIGNALS HIT: (.+)', entry, re.MULTILINE)
            # item (b): capture the LEARNED rule ids (R-) that drove this verdict
            # (F5 attribution). S- defaults are out of scope for owner review, so
            # they are filtered out here; the list feeds the APPROVE token entry
            # and, on a later rescue, the rule-review queue.
            rule_match = re.search(r'^\s*RULE IDS: (.+)', entry, re.MULTILINE)
            rule_ids = ([x.strip() for x in rule_match.group(1).split(",")
                         if x.strip().startswith("R-")] if rule_match else [])

            spam_entry = {
                "time": ts.strftime("%I:%M %p").lstrip("0"),
                "from": from_match.group(1).strip() if from_match else "Unknown",
                "subject": subj_match.group(1).strip() if subj_match else "Unknown",
                "confidence": conf_match.group(1) if conf_match else "?",
                "signals": sig_match.group(1).strip() if sig_match else "",
                "account": acct_name,
                "dry_run": "would move to" in entry,
                "rule_ids": rule_ids,
                # Finding #6: what junked it ("subject_keyword",
                # "pre_classifier", or "ai") — the APPROVE handler branches
                # on this so its ack is truthful per block type.
                "block_source": block_source,
            }
            result["spam_entries"].append(spam_entry)
        elif "No action taken" in entry or "NOT SPAM" in entry:
            result["not_spam"] += 1
            result["per_account"][acct_name]["not_spam"] += 1

    logger = logging.getLogger("daily_report")
    logger.info(
        f"parse_decisions_24h: window={window_start.isoformat()}..{window_end.isoformat()}, "
        f"per_account_keys={sorted(result.get('per_account', {}).keys())}"
    )
    return result


def build_report_body(config: dict, decisions: dict, last_run: datetime,
                      runs_24h: int, signals_data: dict,
                      wl_additions: list = None, wl_domains: dict = None,
                      wl_passthrough: int = 0,
                      token_usage: dict = None, api_key: str = "",
                      sig_status: dict = None,
                      bl_additions: list = None, bl_blocked: tuple = None,
                      bl_totals: tuple = None,
                      window_start=None, window_end=None,
                      rule_reviews_ordered: list = None) -> str:
    """Build the plain text email body.

    ``rule_reviews_ordered`` (item (b)): the ordered pending learned-rule
    reviews to render (primary report only; None/[] renders nothing). The
    numbering here must match build_rule_review_entries fed from the SAME list.
    """
    now = datetime.now()
    date_str = now.strftime("%B %d, %Y")
    time_str = now.strftime("%I:%M %p").lstrip("0")

    lines = []

    lines.append("SPAM FILTER DAILY REPORT")
    lines.append(f"{date_str} — {time_str}")
    # Period covered — only when an explicit window is supplied AND it spans more
    # than one calendar date (a catch-up run). The single-date path (params None,
    # or a one-day window) stays byte-identical to the original report.
    if (window_start is not None and window_end is not None
            and window_start.date() != window_end.date()):
        _fmt = "%b %d %I:%M %p"
        lines.append(f"Period covered: {window_start.strftime(_fmt)} – "
                     f"{window_end.strftime(_fmt)}")
    lines.append("=" * 40)
    lines.append("")

    # Filter status
    lines.append("FILTER STATUS")
    if last_run:
        delta = now - last_run
        minutes_ago = int(delta.total_seconds() / 60)
        if minutes_ago < 60:
            ago_str = f"{minutes_ago} minutes ago"
        else:
            hours_ago = minutes_ago // 60
            ago_str = f"{hours_ago} hours ago"

        lines.append(f"Last run: {last_run.strftime('%Y-%m-%d %H:%M:%S')} ({ago_str})")

        if delta > timedelta(hours=25):
            lines.append(
                f"WARNING: Filter has not run in over 25 hours — "
                f"last run: {last_run.strftime('%Y-%m-%d %H:%M:%S')}"
            )
    else:
        lines.append("Last run: UNKNOWN (no runs found in log)")
        lines.append("WARNING: No filter runs detected")

    lines.append(f"Runs in last 24h: {runs_24h}")
    lines.append("")

    # Activity
    accounts = [a for a in config.get("accounts", []) if a.get("enabled", True)]
    acct_names = ", ".join(a["name"] for a in accounts)

    lines.append("ACTIVITY — LAST 24 HOURS")

    if len(decisions["per_account"]) > 1:
        # Multi-account breakdown
        lines.append(f"Accounts monitored: {len(accounts)} ({acct_names})")
        lines.append("")
        for acct_name, counts in decisions["per_account"].items():
            lines.append(f"  {acct_name}:")
            lines.append(f"    Emails evaluated: {counts['evaluated']}")
            lines.append(f"    Spam moved: {counts['spam']}")
            lines.append(f"    Passed through: {counts['not_spam']}")
        lines.append("")
        lines.append(f"TOTALS:")
    else:
        lines.append(f"Accounts monitored: {len(accounts)} ({acct_names})")

    dry_run = config.get("filter", {}).get("dry_run", True)
    spam_dry_run = decisions.get("spam_dry_run", 0)

    lines.append(f"Emails evaluated: {decisions['evaluated']}")
    lines.append(f"Spam moved to Junk: {decisions['spam_moved']}")
    # In Dry Run, spam is detected but never moved. Always surface the count
    # when Dry Run is on (show 0 so the mode is visible), or whenever any
    # dry-run detections exist.
    if dry_run or spam_dry_run > 0:
        lines.append(f"Spam detected (Dry Run — not moved): {spam_dry_run}")
    lines.append(f"Passed through (not spam): {decisions['not_spam']}")
    lines.append(f"Errors: {decisions['errors']}")
    lines.append("")

    # Spam details — split moved vs dry-run entries so each gets its own header
    moved_entries = [e for e in decisions["spam_entries"] if not e.get("dry_run")]
    dry_run_entries = [e for e in decisions["spam_entries"] if e.get("dry_run")]
    multi_acct = len(decisions["per_account"]) > 1

    def _render_spam_list(entry_list, start_index=1):
        for i, spam in enumerate(entry_list, start_index):
            prefix = f"{spam['account']}: " if multi_acct else ""
            # Feature 3: flag mail junked by a HARD pre-classifier tripwire (no AI
            # review) so a rare mistake stands out in the digest.
            tripwire = spam.get("block_source") == "pre_classifier"
            marker = "[TRIPWIRE] " if tripwire else ""
            lines.append(f"{i}. {marker}{spam['time']} | {prefix}{spam['from']}")
            lines.append(f"   SUBJECT: {spam['subject']}")
            lines.append(
                f"   CONFIDENCE: {spam['confidence']} | "
                f"SIGNALS: {spam['signals']}"
            )
            if tripwire:
                lines.append(
                    "   Junked by a built-in tripwire "
                    f"({_tripwire_reason(spam.get('signals', ''))}) — no AI "
                    f"review. If it's legitimate, reply APPROVE {i} to rescue "
                    "this sender.")
            lines.append("")

    if moved_entries:
        lines.append("SPAM MOVED TO JUNK")
        lines.append("-" * 39)
        _render_spam_list(moved_entries)
        lines.append("-" * 39)
        lines.append("")
        lines.append("If any of the above are NOT spam, move them back from your Junk folder.")
        lines.append("To review recent decisions, open MailWarden and view the Home tab.")

    if dry_run_entries:
        lines.append("SPAM DETECTED — DRY RUN, NOT MOVED")
        lines.append("-" * 39)
        # One unified 1..k numbering space across moved + dry-run entries, so
        # an APPROVE <n> reply is unambiguous (safe sender-approval feature).
        _render_spam_list(dry_run_entries, start_index=len(moved_entries) + 1)
        lines.append("-" * 39)
        lines.append("")
        lines.append("To review recent decisions, open MailWarden and view the Home tab.")

    if moved_entries or dry_run_entries:
        lines.append("")
        lines.append("To rescue a sender, reply to this report with APPROVE and the item number (example: APPROVE 3). MailWarden will trust mail from that sender's domain going forward. If an item was blocked by a rule you set yourself, MailWarden will reply with how to change that rule instead.")

    if not moved_entries and not dry_run_entries:
        lines.append("No spam moved to Junk in the last 24 hours.")

    # API usage block — primary recipient only (gated by token_usage presence)
    if token_usage:
        lines.append("")
        lines.extend(build_api_usage_section(config))

    lines.append("")

    # Signal learner status
    learner = config.get("signal_learner", {})
    # Prefer the learner's own state file (L3); fall back to the legacy config
    # value so installs that predate the change still show an accurate "Last ran".
    last_scan = None
    try:
        with open(LEARNER_STATE_PATH, "r") as f:
            last_scan = json.load(f).get("last_scan_timestamp")
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    if not last_scan:
        last_scan = learner.get("last_scan_timestamp")
    sig_version = learner.get("signals_version", "1.0")
    derived = signals_data.get("derived_from_examples", 0)

    lines.append("SIGNAL LEARNER")
    if last_scan:
        lines.append(f"Last ran: {last_scan}")
    else:
        lines.append("Last ran: Never (no examples processed yet)")
    lines.append(f"Current signals version: {sig_version} (derived from {derived} examples)")

    # Whitelist activity — only show if there was activity
    has_wl_additions = wl_additions and len(wl_additions) > 0
    has_wl_domain_changes = wl_domains and (wl_domains.get("added") or wl_domains.get("removed"))
    has_wl_passthrough = wl_passthrough > 0

    if has_wl_additions or has_wl_domain_changes or has_wl_passthrough:
        lines.append("")

        if has_wl_additions or has_wl_domain_changes:
            lines.append("WHITELIST ACTIVITY")

            if has_wl_additions:
                lines.append(f"New addresses added today: {len(wl_additions)}")
                for a in wl_additions:
                    lines.append(f"  + {a['address']} (from: dragged .eml)")

            if has_wl_domain_changes:
                for d in wl_domains.get("added", []):
                    lines.append(f"  + domain {d} added")
                for d in wl_domains.get("removed", []):
                    lines.append(f"  - domain {d} removed")

            if wl_domains:
                total = wl_domains.get("total", 0)
                if has_wl_domain_changes:
                    lines.append(f"Domain list: {total} domains active (changed)")
                else:
                    lines.append(f"Domain list: {total} domains active (unchanged)")

            if has_wl_passthrough:
                lines.append(f"Emails passed via whitelist in last 24h: {wl_passthrough}")
        else:
            # Only passthrough count, no additions or domain changes
            lines.append("WHITELIST")
            lines.append(f"Emails passed via whitelist: {wl_passthrough}")

    # Blacklist section — always shown
    lines.append("")
    bl_blocked_count = bl_blocked[0] if bl_blocked else 0
    bl_blocked_entries = bl_blocked[1] if bl_blocked else []
    bl_total_addrs = bl_totals[0] if bl_totals else 0
    bl_total_names = bl_totals[1] if bl_totals else 0
    has_bl_additions = bl_additions and len(bl_additions) > 0
    has_bl_activity = has_bl_additions or bl_blocked_count > 0

    if has_bl_activity:
        lines.append("BLACKLIST ACTIVITY")
        if has_bl_additions:
            lines.append(f"New entries added today: {len(bl_additions)}")
            for a in bl_additions:
                parts = []
                if a.get("address"):
                    parts.append(f"{a['address']} (address)")
                if a.get("display_name"):
                    parts.append(f"{a['display_name']} (display name)")
                entry_desc = ", ".join(parts) if parts else "(nothing added)"
                lines.append(f"  + {entry_desc} — via {a.get('source', 'unknown')}")
            lines.append("")

        if bl_blocked_count > 0:
            lines.append(f"Emails blocked in last 24h: {bl_blocked_count}")
            for b in bl_blocked_entries:
                lines.append(f"  - {b['time']} | {b['from']}")
                if b.get("subject"):
                    lines.append(f"    \"{b['subject'][:60]}\" [matched: {b['match_type']}]")
            # Finding #6: blacklist blocks are the owner's own rules, so they
            # are not APPROVE-able above — point to the real undo per type.
            lines.append("To unblock one of these senders: for an address or name, forward a message from that sender with the subject \"Fwd: Remove from Blacklist\". For a domain or subject keyword, open the Dashboard's Blacklist tab, select the entry, and click Remove.")
            lines.append("")

        lines.append(f"Blacklist totals: {bl_total_addrs} addresses | {bl_total_names} display names")
    else:
        lines.append("BLACKLIST")
        lines.append(f"Emails blocked today: 0")
        lines.append(f"Totals: {bl_total_addrs} addresses | {bl_total_names} display names")

    # Pending signal reviews
    if sig_status:
        sig_lines = build_pending_signals_section(sig_status)
        if sig_lines:
            lines.extend(sig_lines)

    # item (b): learned-rule review (primary report only — passed by the caller)
    if rule_reviews_ordered:
        rr_lines = build_rule_review_section(rule_reviews_ordered)
        if rr_lines:
            lines.extend(rr_lines)

    lines.append("")
    lines.append("=" * 40)

    dry_run = config.get("filter", {}).get("dry_run", True)
    mode = "DRY RUN" if dry_run else "LIVE"
    lines.append(f"Spam Filter [{mode}] | {PROJECT_ROOT}")

    return "\n".join(lines)


def send_report(config: dict, subject: str, body: str, logger: logging.Logger,
                to_addr: str = ""):
    """Send the report email via SMTP. If to_addr is empty, falls back to
    config.summary.recipient or config.summary.recipient_address."""
    smtp_config = config.get("smtp", {})
    summary_config = config.get("summary", {})

    host = smtp_config.get("host", "")
    port = smtp_config.get("port", 587)
    username = smtp_config.get("username", "")
    password = smtp_config.get("password", "")
    from_addr = smtp_config.get("from_address", username)
    if not to_addr:
        to_addr = (summary_config.get("recipient")
                   or summary_config.get("recipient_address")
                   or username)
    use_starttls = smtp_config.get("use_starttls", True)

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    # Stamp the daily report as MailWarden system mail, exactly like
    # spam_filter.send_email (~1866), so the filter's loop-top self-loop guard
    # recognises and skips it on re-ingestion instead of junking the very report
    # that quotes junked mail. Without this the report's only protection was the
    # MWR body-prefix guard, which is unreachable once the owner/auth checks null
    # out mwr_match (the report is sent from the single global SMTP identity to
    # each account, and the owner's server may carry no Authentication-Results).
    msg["X-MailWarden-System"] = "1"

    def _smtp_send():
        # The stamped SMTP path — now the FALLBACK when IMAP APPEND is
        # unavailable (recipient is not a configured account) or fails.
        # Retry transient/network failures; permanent errors (auth, refused
        # recipient/sender, data) raise immediately. PERMANENT is checked first
        # because smtplib exceptions are OSError subclasses.
        permanent = (smtplib.SMTPAuthenticationError,
                     smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused,
                     smtplib.SMTPDataError, smtplib.SMTPNotSupportedError)
        transient = (smtplib.SMTPConnectError, smtplib.SMTPHeloError,
                     smtplib.SMTPServerDisconnected, TimeoutError,
                     ConnectionError, OSError)
        attempts = 3
        backoffs = [2, 4]  # seconds before attempts 2 and 3
        for attempt in range(1, attempts + 1):
            server = None
            try:
                from utils import smtp_login
                server = smtp_login(smtp_config)
                server.sendmail(from_addr, [to_addr], msg.as_string())
                logger.info(f"Daily report sent to {to_addr}")
                return
            except permanent as e:
                logger.error(f"SMTP to {to_addr} failed (permanent, no retry): {e}")
                raise
            except transient as e:
                if attempt >= attempts:
                    logger.error(f"SMTP to {to_addr} failed after {attempts} attempts: {e}")
                    raise
                logger.warning(f"SMTP to {to_addr} transient failure "
                               f"(attempt {attempt}/{attempts}): {e}; retrying")
                time.sleep(backoffs[attempt - 1])
            except Exception as e:
                logger.error(f"SMTP to {to_addr} failed: {e}")
                raise
            finally:
                if server:
                    try:
                        server.quit()
                    except Exception:
                        pass

    # Changeset 3: deliver the report by IMAP APPEND into the owner's mailbox
    # (bypasses the SMTP transit filters that junk self-addressed system mail),
    # with the stamped SMTP retry path above as the never-lose fallback.
    # deliver_owner_mail also backfills Date + Message-ID (APPEND omits them).
    from utils import deliver_owner_mail
    deliver_owner_mail(config, msg, to_addr, logger, _smtp_send)


def main(now=None):
    logger = setup_logging()
    logger.info("=" * 60)
    logger.info("Daily report starting")

    now = now if now is not None else datetime.now()

    config = load_config()
    signals_data = load_signals()
    api_key = config.get("anthropic", {}).get("api_key", "")

    # --- Token usage: load, prune old records, save ---
    # The report is the SOLE 90-day pruner of token_usage.json (the filter and
    # learner only merge-append). Hold the lock across load->prune->save.
    with file_lock.locked(TOKEN_USAGE_PATH):
        token_usage = load_token_usage()
        token_usage = prune_token_usage(token_usage)
        save_token_usage(token_usage)

    # --- Pending signal expiry cleanup ---
    logger.info("Checking pending signal proposals...")
    sig_status = expire_pending_signals(logger)

    # --- item (b): learned-rule review queue (prune stale, then render on the
    # PRIMARY report only — one owner, so a single prompt avoids duplicating the
    # same rule across every account's report). ---
    rule_reviews_queue = prune_rule_reviews(logger)
    rule_reviews_ordered = ordered_rule_reviews(rule_reviews_queue, signals_data)
    rule_review_entries = build_rule_review_entries(rule_reviews_ordered)

    # --- Current whitelist/blacklist snapshots (NOT windowed) ---
    wl_additions = []
    wl_domains = {"added": [], "removed": [], "total": 0}
    whitelist = load_whitelist()
    wl_domains["total"] = len(whitelist.get("domains", []))

    bl_additions = []
    blacklist = load_blacklist()
    bl_totals = (len(blacklist.get("addresses", [])),
                 len(blacklist.get("display_names", [])))

    date_str = now.strftime("%B %d, %Y")

    # --- Per-account calendar-day windows + watermark (C10) ---
    # Each account advances ITS OWN watermark only on ITS OWN successful send;
    # one account's failure never touches another's window.
    with file_lock.locked(REPORT_STATE_PATH):
        report_state = load_report_state()
    state_accounts = report_state.get("accounts", {})
    advances = {}

    def _window_for(name):
        return compute_report_window(
            now, _parse_state_ts(
                state_accounts.get(name, {}).get("last_report_through")))

    accounts = [a for a in config.get("accounts", []) if a.get("enabled", True)]

    if not accounts:
        # Fallback: single aggregate report to summary.recipient.
        name = "__aggregate__"
        window_start, window_end = _window_for(name)
        if window_start == window_end:
            logger.info(f"{name}: already reported through "
                        f"{window_end.isoformat()}; nothing new to send.")
        else:
            wl_passthrough = count_whitelisted_passthrough_24h(window_start, window_end)
            bl_blocked = count_blacklisted_blocked_24h(window_start, window_end)
            decisions = parse_decisions_24h(window_start, window_end)
            last_run, runs_24h, errors_24h = get_last_filter_run(window_start, window_end)
            decisions["errors"] = errors_24h
            orphaned = decisions.get("per_account", {}).get("Unknown", {}).get("evaluated", 0)
            if orphaned:
                logger.warning(
                    f"{orphaned} decision(s) in the window had no ACCOUNT: tag "
                    f"and will not appear in any per-account report")
            body = build_report_body(
                config, decisions, last_run, runs_24h, signals_data,
                wl_additions=wl_additions, wl_domains=wl_domains,
                wl_passthrough=wl_passthrough,
                token_usage=token_usage, api_key=api_key,
                sig_status=sig_status,
                bl_additions=bl_additions, bl_blocked=bl_blocked,
                bl_totals=bl_totals,
                window_start=window_start, window_end=window_end,
                rule_reviews_ordered=rule_reviews_ordered,
            )
            subject = (f"MailWarden Report — {date_str} — "
                       f"{decisions['spam_moved']} moved to Junk")
            # Safe sender-approval + item (b): reports that list junked entries
            # OR carry pending rule-reviews get a short reply token; otherwise
            # no token is written.
            approval_entries = build_approval_entries(decisions)
            if approval_entries or rule_review_entries:
                approval_token = random_token()
                subject += f" [MWR-{approval_token}]"
                record_report_approvals(approval_token, name, window_end,
                                        approval_entries, logger,
                                        rule_reviews=rule_review_entries)
            try:
                send_report(config, subject, body, logger)
                advances[name] = {
                    "last_report_through": window_end.isoformat(),
                    "last_success_at": datetime.now().isoformat(),
                }
            except Exception as e:
                logger.error(f"Failed to send daily report: {e}")
    else:
        for idx, account in enumerate(accounts):
            is_primary = (idx == 0)
            acct_name = account.get("name", "Unknown")
            acct_user = account.get("username", "")
            if not acct_user:
                logger.warning(f"Skipping report for account {acct_name!r}: no email address")
                continue

            window_start, window_end = _window_for(acct_name)
            if window_start == window_end:
                logger.info(f"{acct_name}: already reported through "
                            f"{window_end.isoformat()}; skipping.")
                continue

            wl_passthrough = count_whitelisted_passthrough_24h(window_start, window_end)
            bl_blocked = count_blacklisted_blocked_24h(window_start, window_end)
            decisions = parse_decisions_24h(window_start, window_end)
            last_run, runs_24h, errors_24h = get_last_filter_run(window_start, window_end)
            decisions["errors"] = errors_24h

            orphaned = decisions.get("per_account", {}).get("Unknown", {}).get("evaluated", 0)
            if orphaned:
                logger.warning(
                    f"{orphaned} decision(s) in {acct_name}'s window had no "
                    f"ACCOUNT: tag and will not appear in any per-account report")

            all_per = decisions.get("per_account", {})
            per_acct = all_per.get(acct_name, {})
            if not per_acct:
                norm_target = acct_name.strip().lower()
                for log_key, log_val in all_per.items():
                    if log_key.strip().lower() == norm_target:
                        per_acct = log_val
                        logger.warning(
                            f"Daily report: account {acct_name!r} matched log key "
                            f"{log_key!r} via tolerant lookup. Consider renaming for "
                            f"exact match in future entries.")
                        break
            acct_decisions = {
                "evaluated": per_acct.get("evaluated", 0),
                "spam_moved": per_acct.get("spam", 0),
                "spam_dry_run": per_acct.get("spam_dry_run", 0),
                "not_spam": per_acct.get("not_spam", 0),
                "errors": decisions.get("errors", 0),  # runtime errors are global
                "spam_entries": [e for e in decisions.get("spam_entries", [])
                                 if e.get("account") == acct_name],
                "per_account": {acct_name: per_acct},
            }

            body = build_report_body(
                config, acct_decisions, last_run, runs_24h, signals_data,
                wl_additions=wl_additions, wl_domains=wl_domains,
                wl_passthrough=wl_passthrough,
                token_usage=(token_usage if is_primary else None),
                api_key=(api_key if is_primary else ""),
                sig_status=(sig_status if is_primary else {}),
                bl_additions=bl_additions, bl_blocked=bl_blocked,
                bl_totals=bl_totals,
                window_start=window_start, window_end=window_end,
                # item (b): learned-rule review renders on the PRIMARY report
                # only (one owner; avoids duplicating a rule across accounts).
                rule_reviews_ordered=(rule_reviews_ordered if is_primary
                                      else None),
            )
            subject = (f"MailWarden Report — {acct_name} — {date_str} — "
                       f"{acct_decisions['spam_moved']} moved to Junk")
            # Safe sender-approval + item (b): junked entries OR (primary-only)
            # pending rule-reviews get a short reply token; else no token.
            acct_rule_review_entries = (rule_review_entries if is_primary
                                        else {})
            approval_entries = build_approval_entries(acct_decisions)
            if approval_entries or acct_rule_review_entries:
                approval_token = random_token()
                subject += f" [MWR-{approval_token}]"
                record_report_approvals(approval_token, acct_name, window_end,
                                        approval_entries, logger,
                                        rule_reviews=acct_rule_review_entries)
            try:
                send_report(config, subject, body, logger, to_addr=acct_user)
                advances[acct_name] = {
                    "last_report_through": window_end.isoformat(),
                    "last_success_at": datetime.now().isoformat(),
                }
            except Exception as e:
                logger.error(f"Failed to send report to {acct_user}: {e}")
                # keep going — one account's failure must not affect others

    # Write advances ONCE, after the loop. Orphaned/removed-account entries are
    # left intact (not pruned).
    if advances:
        with file_lock.locked(REPORT_STATE_PATH):
            fresh = load_report_state()
            fresh.setdefault("accounts", {}).update(advances)
            save_report_state(fresh)

    logger.info("Daily report complete")
    logger.info("=" * 60)


if __name__ == "__main__":
    # Safety net: ensure logging handlers exist, then run the report guarded so
    # any uncaught exception is written to the report's log file (not just
    # stderr, which the SMAppService/launchd agent does not capture) before the
    # process exits non-zero.
    setup_logging()
    try:
        main()
    except Exception:
        logging.getLogger("daily_report").exception("Daily report crashed")
        sys.exit(1)

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Dev-only IMAP junk-folder harvest tool. READ-ONLY export of raw .eml from the
owner's own accounts' junk/spam folders into a LOCAL-ONLY directory, tagged by
provenance but NEVER auto-labeled.

CRITICAL: junk-folder contents are NOT ground-truth spam. They mix MailWarden's
own deposits (including months of its own false positives), SpamAssassin
catches, and the provider's verdicts. This tool never labels anything as spam
or legit — it only exports and tags provenance. Ground truth comes solely from
Matt's y/n verdicts in tools/triage_candidates.py.

Provenance split (metadata only, written to a sidecar TSV; never a corpus label):
  spamassassin — X-Spam-Status/X-Spam-Flag: Yes present
  mailwarden   — Message-ID found in a COPIED decisions.log with a
                 "[MOVED to ...Junk...]" action (the M1 log lives on another
                 machine; pass it via --decisions-log)
  provider     — everything else

Safety: connects read-only. Issues only SELECT / UID SEARCH / UID FETCH
(BODY.PEEK[]). It never issues any mailbox-mutating command and never sets the
Seen flag, so the mailbox is never modified. Large folders are capped/paginated.

Reuses the app's own connect_imap / fetch_raw_email. Account config is read
from ~/MailWarden/config/config.json directly (NOT spam_filter.load_config,
which binds to the stale payload tree).

Usage:
  tests/.venv/bin/python tools/harvest_junk.py --dry-run
  tests/.venv/bin/python tools/harvest_junk.py --account AOL --max-per-account 200
  tests/.venv/bin/python tools/harvest_junk.py --decisions-log ~/Desktop/decisions.log

No API cost. No Anthropic calls.
"""
import argparse
import email as _email_stdlib
import hashlib
import json
import logging
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "payload" / "MailWarden" / "src"))

CONFIG_PATH = Path.home() / "MailWarden" / "config" / "config.json"
DEFAULT_OUT = Path.home() / "Desktop" / "MailWarden-Benchmark" / "_harvest"

_PROVIDER_HEADERS = re.compile(r"x-spam-(status|flag)", re.IGNORECASE)
_PROVIDER_YES = re.compile(r"\byes\b", re.IGNORECASE)

# decisions.log record lines (see spam_filter.log_decision):
#   MESSAGE-ID: <id>
#   ACTION: [MOVED to Junk] ...
_MSGID_RE = re.compile(r"^\s*MESSAGE-ID:\s*(.+?)\s*$")
_ACTION_RE = re.compile(r"^\s*ACTION:\s*(.+?)\s*$")


def load_accounts(config_path=CONFIG_PATH) -> list:
    """Read the account list from the local MailWarden config."""
    cfg = json.loads(Path(config_path).read_text())
    return cfg.get("accounts", [])


def parse_mailwarden_moved_ids(log_text: str) -> set:
    """Return the set of Message-IDs that MailWarden MOVED to a Junk folder,
    per a copied decisions.log. A message counts only when its record's ACTION
    line indicates a move to Junk (not DRY RUN, not MOVE FAILED)."""
    moved = set()
    pending_id = None
    for line in log_text.splitlines():
        m = _MSGID_RE.match(line)
        if m:
            pending_id = m.group(1).strip()
            continue
        a = _ACTION_RE.match(line)
        if a and pending_id is not None:
            action = a.group(1)
            low = action.lower()
            if ("moved to" in low and "junk" in low
                    and "dry run" not in low and "failed" not in low):
                moved.add(pending_id)
            pending_id = None
    return moved


def classify_provenance(raw: bytes, moved_ids: set) -> str:
    """Tag one raw message: 'spamassassin' | 'mailwarden' | 'provider'.

    SpamAssassin marker wins first (it's an intrinsic header); then a
    MailWarden move (join on Message-ID); else provider."""
    msg = _email_stdlib.message_from_bytes(raw)
    for hdr_name in msg.keys():
        if _PROVIDER_HEADERS.match(hdr_name):
            if _PROVIDER_YES.search(msg.get(hdr_name, "")):
                return "spamassassin"
    msgid = (msg.get("Message-ID", "") or "").strip()
    if msgid and msgid in moved_ids:
        return "mailwarden"
    return "provider"


def _safe_name(raw: bytes) -> str:
    """Deterministic content-hash filename (no attacker-controlled bytes on
    disk paths)."""
    return hashlib.sha256(raw).hexdigest()[:16] + ".eml"


def select_junk_folder(conn, account: dict, override=None):
    """SELECT the account's junk folder read-only. Tries the configured name,
    then the INBOX.<name> personal-namespace fallback (mirrors
    scan_train_folder). Returns the selected folder name or None."""
    name = override or account.get("junk_folder") or "Junk"
    for candidate in (f'"{name}"', f'"INBOX.{name}"'):
        try:
            status, _ = conn.select(candidate, readonly=True)
        except Exception:
            status = "NO"
        if status == "OK":
            return candidate
    return None


def harvest_account(conn, account: dict, out_root: Path, moved_ids: set,
                    max_per_account: int, since: str = None,
                    folder_override: str = None, dry_run: bool = False,
                    logger: logging.Logger = None) -> dict:
    """Harvest one account. Returns a summary dict. READ-ONLY throughout.

    ``conn`` is an already-connected IMAP object exposing select/uid (the app's
    IMAP4_SSL, or a fake in tests). We call ONLY select(readonly=True) and
    uid() with the read verbs SEARCH and FETCH — never any mutating verb."""
    import spam_filter
    logger = logger or logging.getLogger("harvest_junk")
    name = account.get("name", account.get("username", "account"))

    selected = select_junk_folder(conn, account, folder_override)
    if not selected:
        return {"account": name, "selected": None, "found": 0,
                "written": 0, "provenance": {}}

    search_args = ["UID", "SEARCH"]
    if since:
        search_args += ["SINCE", since]
    else:
        search_args += ["ALL"]
    status, data = conn.uid(*search_args[1:])
    uids = (data[0].split() if (status == "OK" and data and data[0]) else [])
    # Cap: newest UIDs are highest; take the last N.
    if max_per_account and len(uids) > max_per_account:
        uids = uids[-max_per_account:]

    prov_counts = {"spamassassin": 0, "mailwarden": 0, "provider": 0}
    written = 0
    acct_dir = out_root / re.sub(r"[^A-Za-z0-9._-]", "_", str(name))
    prov_rows = []

    for uid in uids:
        raw = spam_filter.fetch_raw_email(conn, uid, logger)
        if not raw:
            continue
        provenance = classify_provenance(raw, moved_ids)
        prov_counts[provenance] += 1
        fname = _safe_name(raw)
        msgid = (_email_stdlib.message_from_bytes(raw)
                 .get("Message-ID", "") or "").strip()
        prov_rows.append((fname, msgid, provenance))
        if not dry_run:
            acct_dir.mkdir(parents=True, exist_ok=True)
            (acct_dir / fname).write_bytes(raw)
            written += 1

    if prov_rows and not dry_run:
        acct_dir.mkdir(parents=True, exist_ok=True)
        with open(acct_dir / "_provenance.tsv", "w", encoding="utf-8") as fh:
            fh.write("filename\tmessage_id\tprovenance\n")
            for fname, msgid, provenance in prov_rows:
                safe_mid = msgid.replace("\t", " ").replace("\n", " ")
                fh.write(f"{fname}\t{safe_mid}\t{provenance}\n")

    return {"account": name, "selected": selected, "found": len(uids),
            "written": written, "provenance": prov_counts}


def main():
    ap = argparse.ArgumentParser(
        description="READ-ONLY harvest of junk-folder mail (dev-only).")
    ap.add_argument("--account", default=None,
                    help="limit to one configured account by name")
    ap.add_argument("--folder", default=None,
                    help="junk folder override (default: account.junk_folder)")
    ap.add_argument("--max-per-account", type=int, default=500,
                    help="cap messages fetched per account (default: 500)")
    ap.add_argument("--since", default=None,
                    help="IMAP SEARCH SINCE date, e.g. 01-Jan-2026")
    ap.add_argument("--decisions-log", default=None,
                    help="path to a COPIED decisions.log for MailWarden "
                         "provenance join (the live log lives on the M1 machine)")
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help=f"output root (default: {DEFAULT_OUT})")
    ap.add_argument("--dry-run", action="store_true",
                    help="connect, count, print plan; fetch/write nothing")
    ap.add_argument("--yes", action="store_true",
                    help="skip the connect-confirmation prompt")
    args = ap.parse_args()

    import spam_filter
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger("harvest_junk")

    accounts = load_accounts()
    if args.account:
        accounts = [a for a in accounts
                    if a.get("name") == args.account
                    or a.get("username") == args.account]
    if not accounts:
        print("No matching accounts in config.", file=sys.stderr)
        return 1

    moved_ids = set()
    if args.decisions_log:
        try:
            moved_ids = parse_mailwarden_moved_ids(
                Path(args.decisions_log).read_text(errors="replace"))
        except OSError as e:
            print(f"Warning: could not read --decisions-log: {e}", file=sys.stderr)

    if not args.yes:
        print(f"About to connect READ-ONLY to {len(accounts)} account(s): "
              f"{', '.join(a.get('name', a.get('username', '?')) for a in accounts)}")
        print(f"Junk mail will be exported to {args.out} "
              f"(cap {args.max_per_account}/account). No mailbox changes.")
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 0

    out_root = Path(args.out)
    for account in accounts:
        name = account.get("name", account.get("username", "?"))
        try:
            conn = spam_filter.connect_imap(account, logger)
        except Exception as e:
            print(f"  {name}: connect failed: {e}", file=sys.stderr)
            continue
        try:
            summary = harvest_account(
                conn, account, out_root, moved_ids,
                max_per_account=args.max_per_account, since=args.since,
                folder_override=args.folder, dry_run=args.dry_run, logger=logger)
        finally:
            try:
                conn.logout()
            except Exception:
                pass
        p = summary["provenance"]
        verb = "would export" if args.dry_run else "exported"
        print(f"  {summary['account']}: folder={summary['selected']} "
              f"found={summary['found']} {verb}={summary['written'] if not args.dry_run else summary['found']}  "
              f"[spamassassin={p.get('spamassassin', 0)} "
              f"mailwarden={p.get('mailwarden', 0)} provider={p.get('provider', 0)}]")

    print(f"\nProvenance is metadata only — nothing here is labeled. Run "
          f"tools/triage_candidates.py to label into the corpus.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

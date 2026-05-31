#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Produce a scrubbed signals.json for installer shipment.

Reads the developer's live ~/MailWarden/memory/signals.json and emits a version
with all personally-identifiable content removed:

  1. `learner_notes` is replaced with a generic placeholder string.
  2. Any entry in `hard_signals` or `soft_signals` that names a real email
     address, domain, or third-party brand name is stripped.
  3. Entries in `known_sending_infrastructure` that include developer-specific
     hostnames (e.g., box####.bluehost.com) are stripped.
  4. `known_impersonated_brands` are kept as-is (public brand names) but
     de-duplicated case-insensitively.

Writes to ~/MailWarden-installer/resources/defaults/signals.json atomically.

Usage: scripts/scrub_signals.py
"""

import json
import os
import re
import sys
import tempfile
from pathlib import Path

GENERIC_LEARNER_NOTES = (
    "Derived from sample spam patterns. Will expand as users forward "
    "'Fwd: SPAM Example' emails."
)

# Patterns that indicate an entry names a real address, domain, or a specific
# third-party brand/company name (not a generalized pattern description).
REAL_IDENT_PATTERNS = [
    re.compile(r"@[A-Za-z0-9._-]+\.[A-Za-z]{2,}"),                 # any email addr
    re.compile(r"\bbox\d+\.bluehost\.com\b", re.I),                # dev MX
    re.compile(r"\bfirstib\.com\b", re.I),                         # named in dev's REFINEMENT note
    re.compile(r"\bnthmonkey\.com\b", re.I),                       # dev domain
    re.compile(r"\bfirstchairmarketing\.com\b", re.I),             # dev domain
    re.compile(r"\bFirst-Chairbook\b"),                            # dev hostname
    re.compile(r"\bmattrosenberg\b|\bdumbmachine\b", re.I),        # dev username
]

# Infrastructure list — strip entries matching these; keep generalized ones.
INFRA_DEV_PATTERNS = [
    re.compile(r"box\d+\.bluehost\.com", re.I),
    re.compile(r"bluehost\.com as final recipient", re.I),
]


def has_real_identifier(text: str) -> bool:
    return any(p.search(text) for p in REAL_IDENT_PATTERNS)


def is_dev_infra_entry(text: str) -> bool:
    return any(p.search(text) for p in INFRA_DEV_PATTERNS)


def dedupe_ci(items):
    seen = set()
    out = []
    for item in items:
        k = item.lower().strip() if isinstance(item, str) else item
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def atomic_write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
        # tempfile.mkstemp creates files with mode 600 (security default).
        # That's correct for runtime files containing secrets, but this
        # function writes the seed signals.json shipped INSIDE the .app
        # bundle. After .pkg install, the bundle is owned by root:wheel —
        # mode 600 means non-root users get EACCES trying to read it,
        # bootstrap fails, and the app dies on first launch with a Dock
        # bounce and no visible error. Force 644 so the shipped file is
        # world-readable like the other defaults/ files (whitelist.json,
        # blacklist.json, EULA.md, etc.).
        os.chmod(str(path), 0o644)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def scrub(src: dict) -> dict:
    signals = src.get("signals", {})
    hard = [s for s in signals.get("hard_signals", []) if not has_real_identifier(s)]
    soft = [s for s in signals.get("soft_signals", []) if not has_real_identifier(s)]
    infra = [s for s in signals.get("known_sending_infrastructure", [])
             if not is_dev_infra_entry(s) and not has_real_identifier(s)]
    brands = dedupe_ci(signals.get("known_impersonated_brands", []))

    return {
        "version": src.get("version", "1.1"),
        "last_updated": "",
        "derived_from_examples": 0,
        "signals": {
            "hard_signals": hard,
            "soft_signals": soft,
            "known_impersonated_brands": brands,
            "known_sending_infrastructure": infra,
            "learner_notes": GENERIC_LEARNER_NOTES,
        },
    }


def main() -> int:
    src_path = Path.home() / "MailWarden" / "memory" / "signals.json"
    dst_path = Path.home() / "MailWarden-installer" / "resources" / "defaults" / "signals.json"

    if not src_path.exists():
        print(f"ERROR: {src_path} does not exist. Cannot build scrubbed defaults.",
              file=sys.stderr)
        return 1

    with src_path.open() as f:
        src = json.load(f)

    scrubbed = scrub(src)
    atomic_write_json(dst_path, scrubbed)

    # Report what was kept vs. stripped
    src_sig = src.get("signals", {})
    new_sig = scrubbed["signals"]

    def count(obj, key):
        return len(obj.get(key, []))

    print(f"Scrubbed signals.json written to: {dst_path}")
    print(f"  hard_signals:                    {count(src_sig,'hard_signals')} -> {count(new_sig,'hard_signals')}")
    print(f"  soft_signals:                    {count(src_sig,'soft_signals')} -> {count(new_sig,'soft_signals')}")
    print(f"  known_impersonated_brands:       {count(src_sig,'known_impersonated_brands')} -> {count(new_sig,'known_impersonated_brands')}")
    print(f"  known_sending_infrastructure:    {count(src_sig,'known_sending_infrastructure')} -> {count(new_sig,'known_sending_infrastructure')}")
    print(f"  learner_notes:                   replaced with generic string")
    return 0


if __name__ == "__main__":
    sys.exit(main())

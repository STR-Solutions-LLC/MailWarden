#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Fetch a small current batch of trap-collected spam from untroubled.org and
place it into the local benchmark's 1-Spam folder. DEV-ONLY (tools/).

untroubled.org publishes monthly spam archives (trap-collected, so trustworthy
GROUND-TRUTH spam) as .7z files at https://untroubled.org/spam/. This tool
lists the available months, downloads one, extracts N valid messages, and
copies them into ~/Desktop/MailWarden-Benchmark/1-Spam/ as .eml.

Requires the `7z` binary (p7zip) for extraction — it is a SYSTEM dependency,
not a Python one. If `7z` is missing the tool prints the install command and
exits non-zero (never a silent skip).

Usage:
  tests/.venv/bin/python tools/fetch_untroubled.py --list
  tests/.venv/bin/python tools/fetch_untroubled.py                # latest full month, 15 msgs
  tests/.venv/bin/python tools/fetch_untroubled.py --month 2026-06 --count 15
  tests/.venv/bin/python tools/fetch_untroubled.py --yes          # skip confirm

No API cost. No Anthropic calls.
"""
import argparse
import email as _email_stdlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

BASE_URL = "https://untroubled.org/spam/"
DEFAULT_OUT = Path.home() / "Desktop" / "MailWarden-Benchmark" / "1-Spam"

# Monthly archive links look like href="2026-06.7z".
_MONTH_RE = re.compile(r'href="(\d{4}-\d{2})\.7z"', re.IGNORECASE)


def fetch_listing(url=BASE_URL, timeout=30) -> str:
    """Return the raw HTML of the archive index."""
    req = urllib.request.Request(url, headers={"User-Agent": "MailWarden-eval/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def parse_months(html: str) -> list:
    """Return sorted-ascending list of 'YYYY-MM' month archives found."""
    return sorted(set(_MONTH_RE.findall(html)))


def latest_full_month(months: list, current_ym: str) -> str:
    """Pick the newest month that is NOT the current (partial) calendar month.

    ``current_ym`` is 'YYYY-MM' for today. If every available month equals the
    current month (or the list is short), fall back to the newest available.
    """
    prior = [m for m in months if m < current_ym]
    if prior:
        return prior[-1]
    return months[-1] if months else ""


def _valid_messages(extract_dir: Path, count: int) -> list:
    """Return up to `count` paths to files that parse as non-trivial emails.

    Deterministic: files are considered in sorted order. A file qualifies when
    it parses and has a From header and a non-empty body-ish payload.
    """
    picked = []
    for f in sorted(extract_dir.rglob("*")):
        if len(picked) >= count:
            break
        if not f.is_file():
            continue
        try:
            raw = f.read_bytes()
        except OSError:
            continue
        if len(raw) < 40:
            continue
        try:
            msg = _email_stdlib.message_from_bytes(raw)
        except Exception:
            continue
        if not msg.get("From"):
            continue
        picked.append(f)
    return picked


def require_7z() -> str:
    """Return the path to the 7z binary or exit(2) with an install hint."""
    exe = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
    if not exe:
        print("ERROR: the `7z` binary is required to extract untroubled.org "
              "archives but was not found.\n"
              "Install it with:  brew install p7zip", file=sys.stderr)
        raise SystemExit(2)
    return exe


def download(month: str, dest: Path, timeout=120) -> Path:
    """Download the month's .7z archive to dest and return the file path."""
    url = f"{BASE_URL}{month}.7z"
    out = dest / f"{month}.7z"
    req = urllib.request.Request(url, headers={"User-Agent": "MailWarden-eval/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(out, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    return out


def extract(archive: Path, exe: str, dest: Path) -> Path:
    """Extract the archive into dest/extracted and return that directory."""
    outdir = dest / "extracted"
    outdir.mkdir(exist_ok=True)
    subprocess.run([exe, "x", "-y", f"-o{outdir}", str(archive)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return outdir


def place_into_corpus(picked: list, month: str, out_dir: Path) -> list:
    """Copy picked message files into out_dir as normalized .eml. Returns the
    list of destination filenames."""
    out_dir.mkdir(parents=True, exist_ok=True)
    names = []
    for i, src in enumerate(picked, start=1):
        name = f"untroubled-{month}-{i:03d}.eml"
        shutil.copyfile(src, out_dir / name)
        names.append(name)
    return names


def main():
    ap = argparse.ArgumentParser(
        description="Fetch a small untroubled.org spam batch into 1-Spam.")
    ap.add_argument("--month", default=None,
                    help="YYYY-MM archive to fetch (default: latest full month)")
    ap.add_argument("--count", type=int, default=15,
                    help="number of messages to place (default: 15)")
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help=f"destination folder (default: {DEFAULT_OUT})")
    ap.add_argument("--list", action="store_true",
                    help="list available months and exit")
    ap.add_argument("--yes", action="store_true",
                    help="skip the download-confirmation prompt")
    args = ap.parse_args()

    from datetime import datetime
    current_ym = datetime.now().strftime("%Y-%m")

    html = fetch_listing()
    months = parse_months(html)
    if not months:
        print("No monthly archives found at untroubled.org.", file=sys.stderr)
        return 1

    if args.list:
        print("Available months:")
        for m in months:
            tag = "  (current, partial)" if m == current_ym else ""
            print(f"  {m}{tag}")
        print(f"\nLatest full month: {latest_full_month(months, current_ym)}")
        return 0

    month = args.month or latest_full_month(months, current_ym)
    if month not in months:
        print(f"Month {month} not available. Use --list to see options.",
              file=sys.stderr)
        return 1

    # 7z is only needed for the actual fetch, not for --list.
    exe = require_7z()

    if not args.yes:
        print(f"About to download untroubled.org {month}.7z and place "
              f"{args.count} messages into {args.out}.")
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 0

    with tempfile.TemporaryDirectory(prefix="untroubled-") as tmp:
        tmp = Path(tmp)
        print(f"Downloading {month}.7z ...")
        archive = download(month, tmp)
        print(f"Extracting {archive.name} ...")
        extracted = extract(archive, exe, tmp)
        picked = _valid_messages(extracted, args.count)
        if not picked:
            print("No valid messages found in the archive.", file=sys.stderr)
            return 1
        names = place_into_corpus(picked, month, Path(args.out))

    print(f"Placed {len(names)} messages into {args.out}:")
    for n in names:
        print(f"  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

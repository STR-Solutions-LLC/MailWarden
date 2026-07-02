#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Questionable-email y/n triage tool — the labeling gate. Interactive CLI that
shows ONE full harvested email at a time and asks Matt a single question, then
moves ONLY his labeled items into the benchmark corpus.

Ground truth = Matt's human labels, one email at a time. HARD RULE: one email =
one verdict. There is NO group / per-sender / bulk approval of any kind.

Candidate selection (over-flagging is fine by design; Matt's time is the
budget) — a message is a candidate if ANY heuristic fires:
  1. PRIME: DKIM-verified AND brand-matched (the residual-FP fingerprint) —
     computed locally via utils.verify_dkim_locally + summarize_authentication
     + is_authenticated_brand_matched, replicating the production _locally_
     verified_dkim gate (local verify only when trusted A-R has no dkim=).
  2. List-Unsubscribe header present (marketing/transactional infrastructure).
  3. DMARC=pass or SPF=pass with From-domain alignment (authenticated mail).
  4. Registrable dictionary-word From domain whose Message-ID domain matches
     From (plausible real sender; purely lexical, no network).

All DKIM/DNS is local (dkimpy + resolver). NO Anthropic API calls anywhere.

The question wording is EXACTLY:
  "Is this a real company that legitimately has this address?"  [y/n/skip]
NOT "do you want this?" — legit marketing Matt dislikes still counts as
legitimate (the Nordstrom trap).

  y  -> legit  (then n=newsletter/marketing [2-...] or p=personal [3-...])
  n  -> spam   (1-Spam)
  skip -> leave in _harvest, record nothing

Usage:
  tests/.venv/bin/python tools/triage_candidates.py
  tests/.venv/bin/python tools/triage_candidates.py --resume --limit 25

No API cost. No Anthropic calls.
"""
import argparse
import email as _email_stdlib
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "payload" / "MailWarden" / "src"))

DEFAULT_HARVEST = Path.home() / "Desktop" / "MailWarden-Benchmark" / "_harvest"
DEFAULT_BENCHMARK = Path.home() / "Desktop" / "MailWarden-Benchmark"

FOLDER_SPAM = "1-Spam"
FOLDER_NEWSLETTER = "2-Legitimate-Newsletters-and-Marketing"
FOLDER_PERSONAL = "3-Legitimate-Personal"
TRIAGE_LOG = "_triage_log.tsv"

QUESTION = "Is this a real company that legitimately has this address?"

# A short English word list is enough for the "dictionary-word domain"
# heuristic — it only needs to separate 'harborviewdental' from 'bkzvqx'. We
# approximate with a vowel-ratio + length test rather than shipping a dict.
_VOWELS = set("aeiou")


def _headers_dict(msg):
    return {
        "Authentication-Results": msg.get("Authentication-Results", "") or "",
        "Received-SPF": msg.get("Received-SPF", "") or "",
        "DKIM-Signature": msg.get("DKIM-Signature", "") or "",
    }


def _from_domain(msg):
    frm = msg.get("From", "") or ""
    m = re.search(r"[@]([A-Za-z0-9.\-]+)", frm)
    return m.group(1).lower().rstrip(".") if m else ""


def _looks_dictionaryish(label: str) -> bool:
    """Heuristic: the most-significant label of a domain reads like real words
    (has vowels, isn't a random consonant string). Purely lexical."""
    if not label or len(label) < 4:
        return False
    letters = [c for c in label if c.isalpha()]
    if not letters:
        return False
    vowel_ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)
    # random-string spam domains (bkzvqrelay, qentrivo) run vowel-poor.
    return vowel_ratio >= 0.28


def evaluate_candidate(raw: bytes) -> dict:
    """Run the heuristics on one raw message. Returns
    {is_candidate: bool, reasons: [str], from_domain, subject}. Local only."""
    import utils
    import spam_filter

    msg = _email_stdlib.message_from_bytes(raw)
    from_domain = _from_domain(msg)
    reasons = []

    # Local DKIM: replicate _locally_verified_dkim's gate — verify locally ONLY
    # when the trusted Authentication-Results carries no dkim= verdict.
    ar = msg.get("Authentication-Results", "") or ""
    local = None
    if not re.search(r"\bdkim\s*=", ar, re.IGNORECASE):
        if (msg.get("DKIM-Signature", "") or "").strip():
            local = utils.verify_dkim_locally(raw)

    auth = utils.summarize_authentication(
        _headers_dict(msg), from_domain=from_domain, locally_verified=local)

    # 1. PRIME — DKIM-verified AND brand-matched.
    if spam_filter.is_authenticated_brand_matched(auth):
        reasons.append("dkim_brand_matched")

    # 2. List-Unsubscribe present.
    if (msg.get("List-Unsubscribe", "") or "").strip():
        reasons.append("list_unsubscribe")

    # 3. DMARC/SPF pass with From-domain alignment.
    aligned = any(
        d == from_domain or d.endswith("." + from_domain)
        or from_domain.endswith("." + d)
        for d in (auth.get("authenticated_domains") or []))
    if aligned and (auth.get("dmarc") == "pass" or auth.get("spf") == "pass"):
        reasons.append("spf_dmarc_aligned")

    # 4. Dictionary-word From domain whose Message-ID domain matches From.
    msgid = msg.get("Message-ID", "") or ""
    mid_dom = ""
    mm = re.search(r"@([A-Za-z0-9.\-]+)", msgid)
    if mm:
        mid_dom = mm.group(1).lower().rstrip(">").rstrip(".")
    reg_label = from_domain.split(".")[0] if from_domain else ""
    if (from_domain and mid_dom
            and (mid_dom == from_domain or mid_dom.endswith("." + from_domain))
            and _looks_dictionaryish(reg_label)):
        reasons.append("dictionary_domain_msgid_match")

    return {
        "is_candidate": bool(reasons),
        "reasons": reasons,
        "from_domain": from_domain,
        "subject": msg.get("Subject", "") or "",
    }


def _readable_body(msg) -> str:
    """Best-effort readable plain text (plain part, else stripped HTML)."""
    def _decode(part):
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return ""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, "replace")
        except Exception:
            return ""

    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not plain:
                plain = _decode(part)
            elif ct == "text/html" and not html:
                html = _decode(part)
    else:
        if msg.get_content_type() == "text/html":
            html = _decode(msg)
        else:
            plain = _decode(msg)
    if plain.strip():
        return plain
    # crude HTML strip
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def render_email(raw: bytes, reasons: list) -> str:
    """Human-readable one-email view: header summary + readable body."""
    msg = _email_stdlib.message_from_bytes(raw)
    lines = ["=" * 78]
    lines.append(f"From:    {msg.get('From', '')}")
    lines.append(f"To:      {msg.get('To', '')}")
    lines.append(f"Subject: {msg.get('Subject', '')}")
    lines.append(f"Date:    {msg.get('Date', '')}")
    lines.append(f"Flagged by: {', '.join(reasons) or '(none)'}")
    lines.append("-" * 78)
    body = _readable_body(msg)
    lines.append(body[:2000] + ("\n[...truncated...]" if len(body) > 2000 else ""))
    lines.append("=" * 78)
    return "\n".join(lines)


def load_triage_log(benchmark_dir: Path) -> set:
    """Return the set of harvest filenames already labeled (for --resume)."""
    log = benchmark_dir / TRIAGE_LOG
    done = set()
    if log.exists():
        for line in log.read_text(errors="replace").splitlines()[1:]:
            parts = line.split("\t")
            if parts:
                done.add(parts[0])
    return done


def append_triage_log(benchmark_dir: Path, filename: str, verdict: str,
                      destination: str):
    from datetime import datetime
    log = benchmark_dir / TRIAGE_LOG
    new = not log.exists()
    with open(log, "a", encoding="utf-8") as fh:
        if new:
            fh.write("filename\tverdict\tdestination\ttimestamp\n")
        fh.write(f"{filename}\t{verdict}\t{destination}\t"
                 f"{datetime.now().isoformat()}\n")


def place(src: Path, benchmark_dir: Path, folder: str, copy: bool) -> Path:
    dest_dir = benchmark_dir / folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    if copy:
        shutil.copyfile(src, dest)
    else:
        shutil.move(str(src), str(dest))
    return dest


def iter_candidates(harvest_dir: Path):
    """Yield (path, evaluation) for every harvested .eml that is a candidate."""
    for f in sorted(harvest_dir.rglob("*.eml")):
        if not f.is_file():
            continue
        raw = f.read_bytes()
        ev = evaluate_candidate(raw)
        if ev["is_candidate"]:
            yield f, ev


def run_triage(harvest_dir: Path, benchmark_dir: Path, copy=False,
               limit=None, resume=False, prompt=input, out=print) -> dict:
    """Interactive loop. ``prompt`` and ``out`` are seams for testing.

    Enforces the HARD RULE structurally: exactly one prompt per email, no path
    that applies a verdict to more than the single email in hand."""
    done = load_triage_log(benchmark_dir) if resume else set()
    counts = {"y": 0, "n": 0, "skip": 0}
    n_processed = 0

    for src, ev in iter_candidates(harvest_dir):
        if resume and src.name in done:
            continue
        if limit is not None and n_processed >= limit:
            break
        n_processed += 1

        out(render_email(src.read_bytes(), ev["reasons"]))
        ans = prompt(f"{QUESTION} [y/n/skip] ").strip().lower()

        if ans in ("y", "yes"):
            sub = prompt("Newsletter/marketing [n] or personal [p]? ").strip().lower()
            folder = FOLDER_PERSONAL if sub in ("p", "personal") else FOLDER_NEWSLETTER
            dest = place(src, benchmark_dir, folder, copy)
            append_triage_log(benchmark_dir, src.name, "legit", folder)
            counts["y"] += 1
            out(f"-> labeled LEGIT into {folder}: {dest.name}")
        elif ans in ("n", "no"):
            dest = place(src, benchmark_dir, FOLDER_SPAM, copy)
            append_triage_log(benchmark_dir, src.name, "spam", FOLDER_SPAM)
            counts["n"] += 1
            out(f"-> labeled SPAM into {FOLDER_SPAM}: {dest.name}")
        else:
            counts["skip"] += 1
            out("-> skipped (left in _harvest)")

    return {"processed": n_processed, "counts": counts}


def main():
    ap = argparse.ArgumentParser(
        description="Interactive one-email-at-a-time corpus labeling gate.")
    ap.add_argument("--harvest", default=str(DEFAULT_HARVEST),
                    help=f"harvest dir (default: {DEFAULT_HARVEST})")
    ap.add_argument("--benchmark", default=str(DEFAULT_BENCHMARK),
                    help=f"benchmark dir (default: {DEFAULT_BENCHMARK})")
    ap.add_argument("--copy", action="store_true",
                    help="copy into the corpus instead of moving out of _harvest")
    ap.add_argument("--limit", type=int, default=None,
                    help="stop after N candidates this session (resumable)")
    ap.add_argument("--resume", action="store_true",
                    help="skip files already recorded in _triage_log.tsv")
    args = ap.parse_args()

    harvest = Path(args.harvest)
    if not harvest.is_dir():
        print(f"No harvest directory at {harvest}. Run tools/harvest_junk.py "
              f"first.", file=sys.stderr)
        return 1

    result = run_triage(harvest, Path(args.benchmark), copy=args.copy,
                        limit=args.limit, resume=args.resume)
    c = result["counts"]
    print(f"\nDone. {result['processed']} candidates shown — "
          f"legit={c['y']} spam={c['n']} skipped={c['skip']}.")
    print("Only your labeled items entered the corpus.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

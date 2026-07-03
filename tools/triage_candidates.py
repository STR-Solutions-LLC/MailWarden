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

  y  -> legit    (then n=newsletter/marketing [2-...] or p=personal [3-...])
  n  -> spam     (1-Spam)
  g  -> graymail (4-Graymail) — a real sender whose mail is unwanted/relentless
                 pitch mail; scored SEPARATELY by the eval (junking it is never
                 a false positive, missing it is never a recall miss)
  skip -> leave in _harvest, record nothing

Candidates are surfaced INTERLEAVED across the account subdirectories (a
deterministic round-robin over sorted subdirs, each subdir's files sorted;
stray top-level .eml files form one extra bucket taken last), so every sitting
mixes all accounts instead of draining one.

Per-sender cap (--per-domain-cap, default 3; 0 disables): a per-sender LIFETIME
representation cap — at most N examples of any one From-domain AND any one
normalized From display-name end up in the corpus. It is enforced per run via
counters SEEDED at startup from the emails already labeled into the corpus
(the four class folders), then incremented on each ASK. So a sender that
already has N corpus examples is deferred on its very first candidate this run,
with zero asks, and — unlike the old per-run cap — re-running does NOT surface
it again (the seed still reflects those N examples). Hitting either cap only
DEFERS the extra emails: they are NOT asked, NOTHING is written to the log, and
they are LEFT in _harvest. A cap NEVER auto-applies a label; the HARD RULE (one
email = one human verdict) is absolute. The display-name counter catches
political blasts that rotate the From-domain to evade blocking while keeping one
display name; at worst it over-groups a generic name like "Customer Service",
which only defers those — acceptable. An empty/missing display name is never
grouped. Seeding is exception-safe per file (a malformed corpus .eml is skipped)
and deterministic (sorted folders + files). With cap disabled (0/None) the
corpus is not scanned at all.

Browser preview (default ON, disable with --no-preview): each candidate is
ALSO rendered to its own fresh temp HTML file (unique filename per candidate,
so no browser can serve a stale cached tab) and opened in the default
browser, so Matt judges the email AS THE HUMAN SEES IT — the entire lesson of
the HTML-body classifier fix. The preview is hard-sandboxed: a strict CSP
meta (default-src 'none'; img-src data:; style-src 'unsafe-inline';
form-action 'none') blocks ALL remote loads (images/css/fonts/scripts/frames
— blank images are tracking pixels, that blanking is intentional), <script>
blocks are stripped outright (to a fixed point, so splicing tricks can't
reconstruct a live tag), <meta>/<base> tags are renamed to inert unknown
elements so refresh/redirects cannot fire, and every href= is neutralized so
a misclick cannot leave the sandbox. The Terminal text view is unchanged and
remains the fallback if the browser open fails.

Usage:
  tests/.venv/bin/python tools/triage_candidates.py
  tests/.venv/bin/python tools/triage_candidates.py --resume --limit 25
  tests/.venv/bin/python tools/triage_candidates.py --no-preview

No API cost. No Anthropic calls.
"""
import argparse
import email as _email_stdlib
import html as _html_stdlib
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "payload" / "MailWarden" / "src"))

DEFAULT_HARVEST = Path.home() / "Desktop" / "MailWarden-Benchmark" / "_harvest"
DEFAULT_BENCHMARK = Path.home() / "Desktop" / "MailWarden-Benchmark"

FOLDER_SPAM = "1-Spam"
FOLDER_NEWSLETTER = "2-Legitimate-Newsletters-and-Marketing"
FOLDER_PERSONAL = "3-Legitimate-Personal"
# Must match eval_corpus._GRAYMAIL_FOLDER exactly so the eval reader recognizes
# this folder as the (separately-scored) graymail class.
FOLDER_GRAYMAIL = "4-Graymail"
# The four corpus class folders — scanned at startup to SEED the per-sender cap
# so it counts LIFETIME corpus representation, not just this run's asks.
CLASS_FOLDERS = (FOLDER_SPAM, FOLDER_NEWSLETTER, FOLDER_PERSONAL, FOLDER_GRAYMAIL)
TRIAGE_LOG = "_triage_log.tsv"

# Max candidates ASKED per From-domain AND per normalized From display-name per
# run; excess is DEFERRED (never labeled). 0 disables (CLI). The library/test
# default stays None so direct run_triage callers are unaffected.
DEFAULT_PER_DOMAIN_CAP = 3

QUESTION = "Is this a real company that legitimately has this address?"

# The main QUESTION is unchanged; this hint is shown alongside it. Keep it 1-2
# lines — this is dev-only tooling — capturing Matt's approved decision rule.
GUIDANCE = (
    "  (y = real company, filter junking it would be an error  |  "
    "n = deception/con, delivering it would be a failure  |  "
    "g = real but relentless pitch mail, either verdict acceptable)")

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


def _decode_encoded_word(s: str) -> str:
    """Decode any RFC 2047 encoded-words (=?charset?B/Q?...?=) to plain text so
    two differently-encoded copies of the same display name normalize alike.
    Exception-safe: ANY decode failure (malformed encoded-word, unknown charset)
    falls back to the raw string — a bad header must never crash the loop."""
    try:
        from email.header import decode_header
        parts = []
        for chunk, charset in decode_header(s):
            if isinstance(chunk, bytes):
                parts.append(chunk.decode(charset or "utf-8", "replace"))
            else:
                parts.append(chunk)
        return "".join(parts)
    except Exception:
        return s


def _from_display_name(msg) -> str:
    """Normalized From display name for the per-name blast cap: RFC 2047
    decoded, lowercased, whitespace collapsed, surrounding quotes/punctuation
    stripped. Returns "" when there is no display name (bare address) — an empty
    name is NEVER grouped, so distinct empty-name senders can't bunch together."""
    from email.utils import parseaddr
    name, _addr = parseaddr(msg.get("From", "") or "")
    name = _decode_encoded_word(name)
    name = re.sub(r"\s+", " ", name).strip()
    # strip surrounding quotes/punctuation (parseaddr usually removes the outer
    # quotes already; this also handles leading/trailing . , ; : ! ? - _ ' ").
    name = name.strip("\"'.,;:!?-_ ").strip()
    return name.lower()


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
    from_name = _from_display_name(msg)
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
        "from_name": from_name,
        "subject": msg.get("Subject", "") or "",
        # For the browser-preview header bar (additive; nothing else keys on it).
        "auth": (f"SPF={auth.get('spf', 'none')}  "
                 f"DKIM={auth.get('dkim', 'none')}  "
                 f"DMARC={auth.get('dmarc', 'none')}"),
    }


def _body_parts(msg) -> tuple:
    """Return (plain, html) decoded first-parts of the message."""
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
    return plain, html


def _readable_body(msg) -> str:
    """Best-effort readable plain text (plain part, else stripped HTML)."""
    plain, html = _body_parts(msg)
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


# ─── browser preview (sandboxed) ─────────────────────────────────────────────

# Strict CSP injected into every preview: NO remote loads of any kind
# (script/img/css/font/frame/xhr all resolve through default-src 'none';
# only data: images and inline styles are allowed, and forms cannot submit).
# Blank images in the preview ARE the point — they are tracking pixels and
# remote beacons that must never fire while Matt reads harvested junk.
PREVIEW_CSP = ("default-src 'none'; img-src data:; "
               "style-src 'unsafe-inline'; form-action 'none'")


def _remove_script_blocks(h: str) -> str:
    """Drop every <script ...>...</script> span (case-insensitive), belt-and-
    suspenders under the CSP. Linear manual scan (harvested spam is
    adversarial input; no backtracking regexes here). An UNCLOSED <script
    drops everything to end-of-input — in a preview, safety beats fidelity.

    Runs to a FIXED POINT: a single linear pass can be defeated by
    nested/spliced input — e.g. "<scr<script>DUMMY</script>ipt>alert(1)
    </script>" — where deleting the inner span glues the surrounding text
    back into a brand-new, live "<script>" tag that a one-shot scan never
    re-examines. We re-run the pass until output stops changing, so any tag
    reconstructed by a splice gets caught (and removed) on the next pass.
    Each pass only ever deletes characters, so the string is non-increasing
    in length and this always terminates."""
    while True:
        out = []
        pos = 0
        low = h.lower()
        while True:
            i = low.find("<script", pos)
            if i == -1:
                out.append(h[pos:])
                break
            out.append(h[pos:i])
            j = low.find("</script", i + 7)
            if j == -1:
                break                     # unclosed: drop the rest
            k = low.find(">", j)
            if k == -1:
                break
            pos = k + 1
        new_h = "".join(out)
        if new_h == h:
            return new_h
        h = new_h


_NEUTRALIZE_TAG_RE = re.compile(r"(?i)<(/?)\s*(meta|base)\b")

# Matches an `href` attribute assignment in any tag, case-insensitively, in
# every quoting style adversarial HTML can use: double-quoted, single-quoted,
# or bare/unquoted (terminated by whitespace or the tag's closing '>'). The
# leading \b keeps this from matching inside a longer attribute name like
# "data-href" or "hreflang" being followed by more letters before '=' (and if
# it over-matches a harmless custom attribute, that is fine — conservative
# over-neutralizing is the intent). This is a single flat match-and-replace
# (no nested open/close pairing like the <script> stripper), so there is no
# analogous splice risk: we never glue two kept fragments together around a
# deleted middle one that could spell out a new "href=".
_HREF_RE = re.compile(r"""(?i)\bhref\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)""")


def _neutralize_links(h: str) -> str:
    """Neutralize every href= target (any tag, any quoting style, including
    javascript:/data: URIs — CSP already blocks those, but treating all
    hrefs uniformly is simpler and more conservative than special-casing) so
    a misclick can never navigate the real browser off the sandboxed preview.
    The anchor's visible text is untouched — only the navigation target is
    replaced with an inert same-page value."""
    return _HREF_RE.sub('href="#mailwarden-disabled-link"', h)


def _neutralize_email_html(h: str) -> str:
    """Sandbox the email's own HTML: strip scripts, rename <meta>/<base>
    to unknown elements (<x-meta>/<x-base>) the browser ignores — this kills
    meta-refresh redirects and base-URL rewriting without leaving visible
    junk in the render — and neutralize every href= so a misclick can't leave
    the sandbox."""
    h = _remove_script_blocks(h)
    h = _NEUTRALIZE_TAG_RE.sub(r"<\1x-\2", h)
    return _neutralize_links(h)


def build_preview_html(raw: bytes, ev: dict) -> str:
    """Self-contained sandboxed preview page: fixed header bar (ours, clearly
    labeled) + the email as the human sees it (HTML part when present, else
    the plain text in a <pre>)."""
    msg = _email_stdlib.message_from_bytes(raw)
    esc = _html_stdlib.escape
    header = (
        '<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;'
        'font-size:13px;background:#f0f1f4;border:1px solid #c7c9d1;'
        'border-radius:6px;padding:10px 14px;margin:0 0 14px 0;'
        'line-height:1.5">'
        '<div style="font-weight:700">MailWarden triage preview '
        '&mdash; remote content blocked (blank images are tracking '
        'pixels) and links are disabled (clicking cannot leave this '
        'preview)</div>'
        f'<div><b>From:</b> {esc(msg.get("From", "") or "")}</div>'
        f'<div><b>Subject:</b> {esc(msg.get("Subject", "") or "")}</div>'
        f'<div><b>Date:</b> {esc(msg.get("Date", "") or "")}</div>'
        f'<div><b>Auth:</b> {esc(ev.get("auth", "") or "(not evaluated)")}'
        '</div>'
        f'<div><b>Flagged by:</b> '
        f'{esc(", ".join(ev.get("reasons", [])) or "(none)")}</div>'
        '</div>'
    )
    plain, html_part = _body_parts(msg)
    if html_part.strip():
        body = _neutralize_email_html(html_part)
    else:
        body = ('<pre style="white-space:pre-wrap;font-family:Menlo,monospace;'
                f'font-size:13px">{esc(plain)}</pre>')
    return (
        "<!DOCTYPE html>\n<html>\n<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{PREVIEW_CSP}">\n'
        "<title>MailWarden triage preview</title>\n"
        "</head>\n<body>\n"
        f"{header}\n{body}\n"
        "</body>\n</html>\n"
    )


def _open_in_browser(path: Path):
    """Default opener: macOS `open` (default browser). Never raises upward
    into the triage loop — callers wrap us, this just keeps quiet."""
    import subprocess
    subprocess.run(["open", str(path)], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def _ordered_eml_paths(harvest_dir: Path) -> list:
    """Deterministic INTERLEAVED order of every .eml under ``harvest_dir``.

    Round-robin across the immediate account subdirectories (taken in sorted
    name order; each subdir's files sorted by path). Any stray .eml sitting
    directly in ``harvest_dir`` (not in a subdir) forms one extra bucket taken
    LAST. Same inputs -> same order, no randomness. This is what stops one
    account (whose files happen to sort first) from draining a whole sitting."""
    buckets = []
    for d in sorted(p for p in harvest_dir.iterdir() if p.is_dir()):
        files = sorted(f for f in d.rglob("*.eml") if f.is_file())
        if files:
            buckets.append(files)
    stray = sorted(f for f in harvest_dir.glob("*.eml") if f.is_file())
    if stray:
        buckets.append(stray)

    ordered = []
    i = 0
    while any(i < len(b) for b in buckets):
        for b in buckets:
            if i < len(b):
                ordered.append(b[i])
        i += 1
    return ordered


def iter_candidates(harvest_dir: Path):
    """Yield (path, evaluation) for every harvested .eml that is a candidate,
    in the deterministic interleaved order of ``_ordered_eml_paths``."""
    for f in _ordered_eml_paths(harvest_dir):
        ev = evaluate_candidate(f.read_bytes())
        if ev["is_candidate"]:
            yield f, ev


def _seed_sender_counts(benchmark_dir: Path) -> tuple:
    """Seed the per-domain and per-display-name cap counters from emails ALREADY
    in the corpus, so the cap counts LIFETIME representation rather than only
    this run's asks. Scans the four class folders under ``benchmark_dir`` and
    parses each .eml's From with the SAME _from_domain / _from_display_name used
    for candidates (so corpus and candidate sides can never drift).

    Exception-safe PER FILE: a malformed/unreadable corpus .eml is skipped, never
    crashes startup. Empty domain / empty display name are NEVER counted (the
    empty-never-grouped rule). Deterministic: class folders in fixed order, files
    sorted. Returns (domain_counts, name_counts)."""
    domain_counts = {}
    name_counts = {}
    for folder in CLASS_FOLDERS:
        d = benchmark_dir / folder
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.eml")):
            try:
                msg = _email_stdlib.message_from_bytes(f.read_bytes())
                dom = _from_domain(msg)
                nm = _from_display_name(msg)
            except Exception:
                continue                       # skip a malformed corpus file
            if dom:
                domain_counts[dom] = domain_counts.get(dom, 0) + 1
            if nm:
                name_counts[nm] = name_counts.get(nm, 0) + 1
    return domain_counts, name_counts


def run_triage(harvest_dir: Path, benchmark_dir: Path, copy=False,
               limit=None, resume=False, prompt=input, out=print,
               preview=False, opener=None, per_domain_cap=None) -> dict:
    """Interactive loop. ``prompt``, ``out`` and ``opener`` are test seams.

    ``per_domain_cap`` is a per-sender LIFETIME representation cap: at most N
    examples of any one From-domain AND any one normalized From display-name in
    the corpus. Counters are SEEDED at startup from the emails already labeled
    into the corpus (via _seed_sender_counts) and then incremented on each ASK,
    so a sender that already has N corpus examples is deferred on its first
    candidate this run with zero asks, and re-running does not surface it again.
    Hitting EITHER cap DEFERS the extra candidate — it is not asked, nothing is
    written to the log, and it is left in _harvest. A cap NEVER auto-labels;
    deferring is a non-ask, so it cannot violate the HARD RULE. The display-name
    counter catches blasts that rotate the From-domain but keep one display name.
    The library/test default is None (no cap) so direct callers are unaffected
    AND the corpus is not scanned at all; the CLI supplies DEFAULT_PER_DOMAIN_CAP
    (0 disables, also skipping the scan). The end-of-run summary reports the
    deferred tally so deferred mail never looks like it vanished.

    ``preview`` additionally renders each candidate to its OWN sandboxed HTML
    file (a fresh filename per candidate, inside one temp dir — never the
    repo, never the benchmark) and opens it in the default browser so Matt
    judges the email as the human sees it. A unique filename per candidate
    (rather than one reused name) matters because some browsers will serve a
    cached tab for a URL they've already opened instead of the freshly
    written file — a stale email showing under the current prompt is a
    labeling-correctness risk. The CLI turns preview ON by default
    (--no-preview disables); the keyword default stays False so library/test
    callers opt in explicitly. Preview failure of any kind (including the
    `open` call) never interrupts the loop — the Terminal text view below is
    always shown regardless.

    Enforces the HARD RULE structurally: exactly one prompt per email, no path
    that applies a verdict to more than the single email in hand."""
    done = load_triage_log(benchmark_dir) if resume else set()
    counts = {"y": 0, "n": 0, "g": 0, "skip": 0}
    n_processed = 0
    deferred = 0
    # Cap counters. When the cap is active, SEED from the corpus so the cap is a
    # LIFETIME representation cap; when disabled (0/None), do NOT scan the corpus
    # at all (zero behavior change for capless callers). Counters then increment
    # on each ASK, on top of the seed.
    if per_domain_cap:
        asked_per_domain, asked_per_name = _seed_sender_counts(benchmark_dir)
    else:
        asked_per_domain, asked_per_name = {}, {}

    preview_dir = None
    if preview:
        preview_dir = Path(tempfile.mkdtemp(prefix="mailwarden-triage-"))

    for src, ev in iter_candidates(harvest_dir):
        # limit stops the sitting first — deferred items past the cutoff are
        # "not reached", not "deferred", so we don't scan/inflate past it.
        if limit is not None and n_processed >= limit:
            break
        # resume-skip a prior-run label BEFORE any cap counting: it is not an
        # ask this run, so it must not consume this run's per-domain/name budget.
        if resume and src.name in done:
            continue
        # Per-sender cap: defer (do NOT ask, do NOT log, LEAVE in _harvest) when
        # either the domain or the display-name counter has reached the cap.
        # Empty domain / empty name are never grouped.
        dom = ev.get("from_domain") or ""
        nm = ev.get("from_name") or ""
        if per_domain_cap and (
                (dom and asked_per_domain.get(dom, 0) >= per_domain_cap)
                or (nm and asked_per_name.get(nm, 0) >= per_domain_cap)):
            deferred += 1
            continue
        # ---- this candidate is being ASKED ----
        if dom:
            asked_per_domain[dom] = asked_per_domain.get(dom, 0) + 1
        if nm:
            asked_per_name[nm] = asked_per_name.get(nm, 0) + 1
        n_processed += 1

        raw = src.read_bytes()
        out(render_email(raw, ev["reasons"]))
        if preview:
            try:
                # Fresh filename per candidate so no browser can serve a
                # stale cached tab instead of this email's rendered preview.
                preview_path = preview_dir / f"preview-{n_processed:04d}.html"
                preview_path.write_text(build_preview_html(raw, ev),
                                        encoding="utf-8")
                (opener or _open_in_browser)(preview_path)
            except Exception as e:  # never let the browser break the loop
                out(f"[browser preview unavailable ({e}); "
                    f"using the terminal view above]")
        out(GUIDANCE)
        ans = prompt(f"{QUESTION} [y=legit / n=spam / g=graymail (real but "
                     f"unwanted) / skip] ").strip().lower()

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
        elif ans in ("g", "gray", "graymail"):
            dest = place(src, benchmark_dir, FOLDER_GRAYMAIL, copy)
            append_triage_log(benchmark_dir, src.name, "graymail", FOLDER_GRAYMAIL)
            counts["g"] += 1
            out(f"-> labeled GRAYMAIL into {FOLDER_GRAYMAIL}: {dest.name}")
        else:
            counts["skip"] += 1
            out("-> skipped (left in _harvest)")

    return {"processed": n_processed, "counts": counts, "deferred": deferred}


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
    ap.add_argument("--no-preview", action="store_true",
                    help="disable the sandboxed browser preview "
                         "(terminal text only)")
    ap.add_argument("--per-domain-cap", type=int,
                    default=DEFAULT_PER_DOMAIN_CAP,
                    help=f"max candidates asked per sender domain AND per From "
                         f"display-name per run; excess is deferred (left in "
                         f"_harvest, not labeled). 0 disables. "
                         f"(default: {DEFAULT_PER_DOMAIN_CAP})")
    args = ap.parse_args()

    harvest = Path(args.harvest)
    if not harvest.is_dir():
        print(f"No harvest directory at {harvest}. Run tools/harvest_junk.py "
              f"first.", file=sys.stderr)
        return 1

    result = run_triage(harvest, Path(args.benchmark), copy=args.copy,
                        limit=args.limit, resume=args.resume,
                        preview=not args.no_preview,
                        per_domain_cap=(args.per_domain_cap or None))
    c = result["counts"]
    print(f"\nDone. {result['processed']} candidates shown — "
          f"legit={c['y']} spam={c['n']} graymail={c['g']} "
          f"skipped={c['skip']}.")
    if result["deferred"]:
        print(f"{result['deferred']} were held back — their senders already "
              f"have enough labeled examples in the corpus "
              f"(raise --per-domain-cap to include more).")
    print("Only your labeled items entered the corpus.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Shared utility functions for the spam filter system.
"""

import email
import email.header
import email.policy
import html
import ipaddress
import re
import secrets
import smtplib


def random_token(nbytes: int = 6) -> str:
    """Cryptographically random hex token (default 12 hex chars / 48 bits)."""
    return secrets.token_hex(nbytes)


def smtp_login(smtp_config: dict):
    """Connect to SMTP, negotiate encryption, and log in. Returns the
    connected server — caller is responsible for sendmail() + quit().

    Security rule: never send credentials over a truly plaintext
    connection. Resolution:
      port 465                      → smtplib.SMTP_SSL (implicit TLS)
      port != 465, use_starttls=True → SMTP + STARTTLS
      port != 465, use_starttls=False → refuse (RuntimeError)

    The third branch is what protects users who misconfigure their
    account — smtplib.SMTP(host, port).login() happily sends the
    username and password in the clear on an unencrypted socket,
    which is unacceptable.
    """
    host = smtp_config.get("host", "")
    port = int(smtp_config.get("port", 587))
    username = smtp_config.get("username", "")
    password = smtp_config.get("password", "")
    use_starttls = smtp_config.get("use_starttls", True)

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=30)
        server.ehlo()
    else:
        if not use_starttls:
            raise RuntimeError(
                f"Refusing to send SMTP credentials to {host}:{port} "
                f"with TLS disabled. Enable STARTTLS in config.smtp, "
                f"or switch to port 465 for implicit TLS."
            )
        server = smtplib.SMTP(host, port, timeout=30)
        server.ehlo()
        server.starttls()
        server.ehlo()

    server.login(username, password)
    return server


def parse_from_address(header_value: str) -> dict:
    """Extract the display name and email address from a From: header value.

    Returns a dict with 'display_name' and 'address' keys.
    Both may be None if parsing fails or that component is missing.

    Examples:
        '"Biden for America" <info@newdomain.com>'
            -> {"display_name": "Biden for America", "address": "info@newdomain.com"}
        'info@newdomain.com'
            -> {"display_name": None, "address": "info@newdomain.com"}
        '=?utf-8?q?Encoded_Name?= <address@domain.com>'
            -> {"display_name": "Encoded Name", "address": "address@domain.com"}
    """
    result = {"display_name": None, "address": None}

    if not header_value or not isinstance(header_value, str):
        return result

    # Some forwards through HTML intermediaries end up with &lt; &gt; in the
    # plain-text From: value. Decode entities up front so angle-bracket
    # matching works on the normal form.
    header_value = html.unescape(header_value.strip())
    if not header_value:
        return result

    # Decode any RFC 2047 encoded parts
    try:
        decoded_parts = email.header.decode_header(header_value)
        decoded = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(part)
        header_value = " ".join(decoded)
    except Exception:
        pass

    # Try to extract address from angle brackets: Display Name <address@domain.com>
    angle_match = re.search(r'^(.*?)<([^>]+@[^>]+)>\s*$', header_value)
    if angle_match:
        display_name = angle_match.group(1).strip().strip('"').strip("'").strip()
        addr = angle_match.group(2).strip().lower().rstrip(".")
        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', addr):
            result["address"] = addr
            result["display_name"] = display_name if display_name else None
        return result

    # No angle brackets — try the whole string as a bare address
    bare = header_value.strip().strip('"').strip("'").strip()
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', bare):
        result["address"] = bare.lower().rstrip(".")

    return result


def extract_domain(email_address: str) -> str:
    """Extract the @domain.com portion from an email address.

    Returns the lowercase domain with @ prefix, or None if invalid.
    """
    if not email_address or "@" not in email_address:
        return None
    domain = "@" + email_address.split("@", 1)[1].strip().lower().rstrip(".")
    return domain


def _registrable_domain(host: str) -> str:
    """Best-effort registrable domain = last two labels, lowercased.
    NOT public-suffix-aware; acceptable because callers anchor on their OWN
    known hosts / the delivering provider, never arbitrary attacker input."""
    host = (host or "").strip().lower().strip("[]").rstrip(".")
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return host
    return ".".join(labels[-2:])


def select_trusted_auth_results(ar_headers, anchor_hosts) -> str:
    """From all Authentication-Results header values, return the TOPMOST whose
    authserv-id (the token before the first ';') shares a registrable domain with
    the trust anchor. Returns "" if none match (trust nothing — safe direction)."""
    anchor = {_registrable_domain(h) for h in (anchor_hosts or set()) if h}
    anchor.discard("")
    if not anchor:
        return ""
    for ar in ar_headers or []:
        ar = str(ar or "")
        head = ar.split(";", 1)[0].strip()
        authserv = head.split()[0] if head else ""
        if _registrable_domain(authserv) in anchor:
            return ar
    return ""


def get_plain_text_body_from_msg(msg) -> str:
    """Extract the plain text body from an email.message.Message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
    else:
        if msg.get_content_type() == "text/plain":
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
    return ""


# ---------------------------------------------------------------------------
# Pre-classifier signal checks
# (c) 2026 STR Solutions, LLC. All rights reserved.
# ---------------------------------------------------------------------------


def check_auth_results(headers: dict) -> dict:
    """Signal 1: SPF/DKIM/DMARC failures (HARD only).
    Hard: both SPF and DKIM fail. A single failure is NOT a signal — single
    SPF/DKIM failures are common on forwarded/mailing-list mail and are left
    for the AI to judge from the full authentication block.
    Returns {'signal': None | 'SPF_DKIM_BOTH_FAIL', 'detail': str}."""
    auth_results = headers.get("Authentication-Results", "") or ""
    received_spf = headers.get("Received-SPF", "") or ""
    combined = (auth_results + " " + received_spf).lower()

    if not combined.strip():
        return {"signal": None, "detail": ""}

    spf_fail = bool(re.search(r'spf=(fail|softfail|permerror)\b', combined))
    dkim_fail = bool(re.search(r'dkim=(fail|permerror|policy)\b', combined))

    if spf_fail and dkim_fail:
        return {"signal": "SPF_DKIM_BOTH_FAIL", "detail": "Both SPF and DKIM failed"}
    return {"signal": None, "detail": ""}


def summarize_authentication(headers: dict, from_domain: str = "") -> dict:
    """Summarize SPF/DKIM/DMARC results + the cryptographically VERIFIED sending
    domain(s) for the AI classifier (F3). HOST-AGNOSTIC.

    Parses the RFC 8601 ``Authentication-Results`` header — emitted by virtually
    every modern mail provider (Gmail, Outlook/Office365, Yahoo/AOL, Proofpoint,
    cPanel/Exim, Zoho, Fastmail, …) — and the standalone ``Received-SPF`` header.
    It reads only STANDARD tokens (``spf=``, ``dkim=``, ``dmarc=``,
    ``header.from=``, ``header.d=``, ``header.i=@``, ``smtp.mailfrom=``), never
    any host-specific format, so it is independent of the user's email provider.
    Opaque provider-private blobs (X-YMailISG, X-Spam-*, etc.) are ignored.

    Security (audit C5/ARC): ``ARC-Authentication-Results`` is deliberately NOT
    parsed for proven domains — ARC is forgeable, so trusting it would let a
    relay-forged chain claim any sender. The caller is expected to pass only the
    main ``Authentication-Results`` value it has already vetted (see
    ``select_trusted_auth_results``). An advisory ``arc`` verdict is still parsed
    from the (already-trusted) main header for display context only and grants
    NO domain.

    Security: a domain is listed in ``authenticated_domains`` ONLY when the
    relevant check actually PASSED. A bare ``DKIM-Signature: d=`` (an unverified
    *claim* any sender can write) is reported separately as
    ``claimed_dkim_domain`` and is NOT treated as authenticated. When a host
    emits no auth headers at all, every result is ``"none"`` and
    ``authenticated_domains`` is empty — the classifier then judges on other
    evidence (and, per policy, leans toward NOT_SPAM).

    Returns a dict: spf, dkim, dmarc, dmarc_from, spf_mailfrom,
    claimed_dkim_domain, authenticated_domains (sorted), from_domain.
    """
    auth = str(headers.get("Authentication-Results", "") or "")
    received_spf = str(headers.get("Received-SPF", "") or "")
    dkim_sig = str(headers.get("DKIM-Signature", "") or "")

    def _result(token, text):
        m = re.search(r'\b' + token + r'\s*=\s*(\w+)', text, re.IGNORECASE)
        return m.group(1).lower() if m else ""

    def _domain_of(value):
        value = value.strip().strip('<>"').lower()
        if "@" in value:
            value = value.split("@", 1)[1]
        return value.rstrip(".")

    spf = _result("spf", auth)
    if not spf and received_spf:
        spf = (received_spf.strip().split(None, 1)[0] or "").lower()
    dmarc = _result("dmarc", auth)
    dkim_all = [r.lower() for r in re.findall(r'\bdkim\s*=\s*(\w+)', auth, re.IGNORECASE)]
    dkim = "pass" if "pass" in dkim_all else (dkim_all[0] if dkim_all else "")
    arc = _result("arc", auth)

    authenticated = set()

    # DKIM-authenticated domains — correlate each header.d/header.i with ITS OWN
    # dkim= result. Split the Authentication-Results into clauses (RFC 8601 resinfo
    # are ';'-separated) and only harvest from a clause whose own dkim result passed.
    # (A ';' inside a quoted reason="..." only ever fails safe — it can drop a real
    # pass, never admit a forged domain.)
    for clause in auth.split(";"):
        if re.search(r'dkim\s*=\s*pass\b', clause, re.IGNORECASE):
            for m in re.finditer(r'header\.(?:i\s*=\s*@?|d\s*=\s*)([a-z0-9.\-]+)',
                                 clause, re.IGNORECASE):
                authenticated.add(m.group(1).lower().lstrip("@").rstrip("."))

    # DMARC alignment domain (the From: organizational domain) — only when DMARC passed.
    dmarc_from = ""
    m = re.search(r'header\.from\s*=\s*([a-z0-9.\-]+)', auth, re.IGNORECASE)
    if m:
        dmarc_from = m.group(1).lower().rstrip(".")
        if dmarc == "pass":
            authenticated.add(dmarc_from)

    # SPF-authenticated envelope domain — only when SPF passed.
    spf_mailfrom = ""
    m = re.search(r'smtp\.mailfrom\s*=\s*([^\s;()]+)', auth, re.IGNORECASE)
    if m:
        spf_mailfrom = _domain_of(m.group(1))
    if not spf_mailfrom and received_spf:
        m = re.search(r'domain of\s+([^\s)]+)', received_spf, re.IGNORECASE)
        if m:
            spf_mailfrom = _domain_of(m.group(1))
    if spf == "pass" and spf_mailfrom:
        authenticated.add(spf_mailfrom)

    # Unverified DKIM-Signature d= CLAIM(s). A DKIM-Signature header is sender-
    # written and proves nothing on its own — a domain is PROVEN only when its OWN
    # signature passed (added per-clause above) or via aligned DMARC/SPF. We never
    # add a bare d= claim to `authenticated`; we DO surface claimed-but-unproven
    # domains as a phishing signal. The (?:^|[;\s]) guard matches only real d= tags
    # (base64 b= values contain no ';' or whitespace), avoiding false hits.
    claimed = []
    for m in re.finditer(r'(?:^|[;\s])d\s*=\s*([a-z0-9.\-]+)', dkim_sig, re.IGNORECASE):
        dom = m.group(1).lower().rstrip(".")
        if dom and dom not in claimed:
            claimed.append(dom)
    claimed_dkim = claimed[0] if claimed else ""
    claimed_unverified = sorted(d for d in claimed if d not in authenticated)

    return {
        "spf": spf or "none",
        "dkim": dkim or "none",
        "dmarc": dmarc or "none",
        "arc": arc or "none",
        "dmarc_from": dmarc_from,
        "spf_mailfrom": spf_mailfrom,
        "claimed_dkim_domain": claimed_dkim,
        "claimed_unverified_domains": claimed_unverified,
        "authenticated_domains": sorted(authenticated),
        "from_domain": (from_domain or "").lower().lstrip("@").rstrip("."),
    }


def check_spam_score(headers: dict) -> dict:
    """SpamAssassin verdict parser (Bluehost / cPanel).

    IMPORTANT (F1): the ``X-Spam-Score`` header is the SpamAssassin score
    multiplied by TEN — a clean score of 1.6 is stamped as ``X-Spam-Score: 16``.
    Reading that integer as the score made clean mail look like 16 and was a
    primary false-positive source. We now IGNORE ``X-Spam-Score`` entirely and
    read the REAL decimal from ``X-Spam-Status`` (``score=N.N``) plus the verdict
    from ``X-Spam-Flag`` / ``X-Spam-Status``.

    This helper no longer feeds a pre-classifier signal (soft signals were
    removed); it is retained as the shared, regression-guarded parser for the
    ×10 misread and is reused by ``host_spam_verdict``. A genuinely HIGH verdict
    is reported as ``ELEVATED_SPAM_SCORE``:
      - ``X-Spam-Flag: YES``, or
      - ``X-Spam-Status`` verdict ``Yes``, or
      - real decimal score >= 5.0 (SpamAssassin's usual spam threshold; covers
        'tag-only' configs that still deliver flagged mail to the inbox).
    The normal low range is treated as NO signal. AOL/Yahoo do not stamp
    ``X-Spam-*`` at all → no signal there.
    """
    flag_hdr = (headers.get("X-Spam-Flag", "") or "").strip().upper()
    status_hdr = headers.get("X-Spam-Status", "") or ""

    if flag_hdr == "YES":
        return {"signal": "ELEVATED_SPAM_SCORE", "detail": "X-Spam-Flag: YES"}

    # X-Spam-Status looks like:  "No, score=1.6 required=5.0 ..."  or  "Yes, score=7.2 ..."
    if status_hdr:
        if re.match(r'\s*yes\b', status_hdr, re.IGNORECASE):
            return {"signal": "ELEVATED_SPAM_SCORE",
                    "detail": f"X-Spam-Status verdict Yes ({status_hdr.strip()[:60]})"}
        m = re.search(r'score=(-?\d+\.?\d*)', status_hdr, re.IGNORECASE)
        if m:
            try:
                score = float(m.group(1))
                if score >= 5.0:
                    return {"signal": "ELEVATED_SPAM_SCORE",
                            "detail": f"SpamAssassin score {score} (>=5.0)"}
            except ValueError:
                pass

    return {"signal": None, "detail": ""}


def host_spam_verdict(headers: dict) -> dict | None:
    """Present-only summary of the sender's UPSTREAM provider spam verdict.

    Returns ``None`` when no ``X-Spam-*`` header is present at all (the common
    case for AOL/Yahoo and many hosts) — callers MUST omit any spam-score line
    entirely in that case rather than claim "no score"/"unknown". When at least
    one ``X-Spam-Flag`` / ``X-Spam-Status`` header IS present, returns a factual
    dict for the trusted context block::

        {"score": float | None, "flag": "yes" | "no", "verdict": "yes" | "no"}

    ``flag``/``verdict`` are derived via the same parsing as ``check_spam_score``
    (so the ×10 misread can never resurface): a HIGH verdict → "yes", otherwise
    "no". ``score`` is the REAL decimal from ``X-Spam-Status`` (``score=N.N``)
    when present, else None. ``X-Spam-Score`` is never read.
    """
    flag_hdr = (headers.get("X-Spam-Flag", "") or "").strip()
    status_hdr = (headers.get("X-Spam-Status", "") or "").strip()
    if not flag_hdr and not status_hdr:
        return None

    high = check_spam_score(headers)["signal"] == "ELEVATED_SPAM_SCORE"
    score = None
    m = re.search(r'score=(-?\d+\.?\d*)', status_hdr, re.IGNORECASE)
    if m:
        try:
            score = float(m.group(1))
        except ValueError:
            score = None

    verdict = "yes" if high else "no"
    return {"score": score, "flag": verdict, "verdict": verdict}


def _extract_sending_ip(received_headers, own_hosts=None) -> str:
    """Extract the first external (public) sending IP from Received headers.

    Security (M9/M10):
      - Traverse TOP-DOWN: the topmost Received header is added by OUR own mail
        infrastructure and names the host that connected to us (the real sender's
        edge). We do NOT walk the chain in reverse — attacker-forged lower
        Received lines must not win.
      - Skip any header whose ``by``/``from`` host is one of our OWN hosts: that
        is our own relay, not the sender's connecting IP.
      - Only trust IPs in bracketed/parenthesized connecting-IP forms
        (``[1.2.3.4]`` / ``(1.2.3.4)`` / ``[IPv6:..]``), never bare dotted-quads
        appearing in HELO strings, dates, etc. Bracketed is preferred; paren
        forms are consulted only if no bracketed public IP is found.
      - Supports both IPv4 and IPv6; skips any non-public address.
    """
    if not received_headers:
        return None
    if isinstance(received_headers, str):
        received_headers = [received_headers]

    own = {h.strip().lower().rstrip(".") for h in (own_hosts or set()) if h}

    def _first_public(candidates):
        for cand in candidates:
            cand = cand.strip()
            try:
                ip = ipaddress.ip_address(cand)
            except ValueError:
                continue
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                continue
            return str(ip)
        return None

    for hdr in received_headers:
        hdr_str = str(hdr)

        # Skip our own relays: if the 'by' or 'from' host is one of our hosts.
        if own:
            skip = False
            for kw in (r'\bby\s+([^\s;()]+)', r'\bfrom\s+([^\s;()]+)'):
                m = re.search(kw, hdr_str, re.I)
                if m and m.group(1).strip().lower().rstrip(".") in own:
                    skip = True
                    break
            if skip:
                continue

        # Prefer bracketed connecting-IP forms.
        bracketed = re.findall(r'\[(?:IPv6:)?([0-9a-fA-F:.]+)\]', hdr_str)
        result = _first_public(bracketed)
        if result:
            return result

        # Fall back to parenthesized forms only if no bracketed public IP found.
        paren = re.findall(r'\((?:IPv6:)?([0-9a-fA-F:.]+)\)', hdr_str)
        result = _first_public(paren)
        if result:
            return result

    return None


def check_ip_reputation(sending_ip: str, timeout: float = 3.0) -> dict:
    """Signal 7: DNSBL lookup on sending IP (HARD only).
    Hard: listed on 2+ blocklists. A single listing is NOT a signal — single
    DNSBL hits are noisy/often stale and are left for the AI to weigh."""
    if not sending_ip:
        return {"signal": None, "detail": "", "hits": []}

    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return {"signal": None, "detail": "dnspython not installed", "hits": []}

    blocklists = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
    ]

    try:
        ip_obj = ipaddress.ip_address(sending_ip)
    except ValueError:
        return {"signal": None, "detail": "", "hits": []}
    if ip_obj.version == 4:
        reversed_ip = ".".join(reversed(sending_ip.split(".")))
    else:
        # nibble-reversed label without the .ip6.arpa suffix
        reversed_ip = ip_obj.reverse_pointer[:-len(".ip6.arpa")]

    hits = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for bl in blocklists:
        query = f"{reversed_ip}.{bl}"
        try:
            answers = resolver.resolve(query, "A")
            for ans in answers:
                ans_str = str(ans)
                if ans_str.startswith("127."):
                    hits.append(bl)
                    break
        except dns.resolver.NXDOMAIN:
            continue  # not listed
        except (dns.exception.Timeout, dns.resolver.NoNameservers,
                dns.resolver.NoAnswer):
            continue
        except Exception:
            continue

    if len(hits) >= 2:
        return {"signal": "IP_DNSBL_MULTIPLE",
                "detail": f"IP {sending_ip} listed on: {', '.join(hits)}",
                "hits": hits}
    return {"signal": None, "detail": "", "hits": []}


# ---------------------------------------------------------------------------
# Pre-classifier signal: leaked AI generation-prompt detector (ITEM 4)
# (c) 2026 STR Solutions, LLC. All rights reserved.
# ---------------------------------------------------------------------------
#
# These structural markers appear in emails that are accidental LLM prompt
# leaks — the generation instructions were emailed instead of the finished
# HTML. They have essentially zero occurrence in legitimate email.
#
# Calibration:
#   >= 2 distinct markers in subject+body → HARD signal LEAKED_AI_PROMPT
#      (deterministic spam, no API call)
#   fewer than 2 markers → NO signal (left for the AI to judge)
_LEAKED_AI_PROMPT_MARKERS = [
    "=== assignment ===",
    "=== output format ===",
    "=== divergence instructions ===",
    "=== email html rules ===",
    "=== inbox-placement hidden text",
    "run seed:",
    "prompt preset:",
    "creative style mode:",
    "return only the complete html document",
    "you are producing html intended for common email clients",
    "inferred creative strategy",
    "detected campaign type:",
]


def check_leaked_ai_prompt(subject: str, plain_text_body: str) -> dict:
    """Signal 9: Leaked AI generation-prompt content in subject or body (HARD only).

    Counts how many DISTINCT markers from _LEAKED_AI_PROMPT_MARKERS appear
    (case-insensitive) in the combined subject + body text. Only the >= 2
    marker case is a (hard) signal; a single marker is NOT a signal.

    Returns:
        {
          'hard_signal': str or None,   # 'LEAKED_AI_PROMPT' if >= 2 markers
          'detail': str,
          'marker_count': int,
        }
    """
    text = f"{subject or ''}\n{plain_text_body or ''}".lower()
    found = [m for m in _LEAKED_AI_PROMPT_MARKERS if m in text]
    count = len(found)

    if count >= 2:
        return {
            "hard_signal": "LEAKED_AI_PROMPT",
            "detail": (
                f"Leaked AI generation prompt detected: {count} distinct markers "
                f"({', '.join(repr(f) for f in found[:4])}{'...' if count > 4 else ''})"
            ),
            "marker_count": count,
        }
    return {"hard_signal": None, "detail": "", "marker_count": 0}


# ---------------------------------------------------------------------------
# Pre-classifier signal: TRUE prompt-injection HARD tells (ITEM 5)
# (c) 2026 STR Solutions, LLC. All rights reserved.
# ---------------------------------------------------------------------------
#
# Only patterns with essentially zero legitimate occurrence are placed here.
# Broader/ambiguous prompt-injection phrasing is no longer a pre-classifier
# signal; it is left for the AI to judge from the message content.
#
# (a) Our own delimiter tag appearing in received content:
#     <untrusted_email> or </untrusted_email>
#     (We control this tag — its presence in a received email is an attack.)
# (b) Forged AI conversation turns — Anthropic-style \n\nAssistant: / \n\nHuman:
#     or a line beginning with Assistant:/Human:/System: at line start.
# (c) "ignore/disregard/forget … instructions" imperative PAIRED within ~50
#     chars with a classification-manipulation target.
_HARD_INJECTION_PATTERNS = [
    # (a) Our own delimiter tag in inbound content
    re.compile(r'<\s*/?\s*untrusted_email\s*>', re.IGNORECASE),

    # (b) Anthropic-style double-newline conversation turn injection
    re.compile(r'\n\n\s*(?:assistant|human)\s*:', re.IGNORECASE),
    # Line-anchored conversation turn (^ with MULTILINE)
    re.compile(r'(?:^|\n)[ \t]*(?:assistant|human|system)\s*:\s', re.IGNORECASE),
]

# (c) Paired imperative + classification-target (within ~50 chars of each other)
_HARD_INJECTION_IMPERATIVE = re.compile(
    r'(?:ignore|disregard|forget)\b.{0,50}?\b(?:not\s+spam|mark\s+as\s+safe|legitimate|whitelist|don.t\s+flag|classify\s+as)',
    re.IGNORECASE | re.DOTALL,
)


def check_hard_prompt_injection(subject: str, plain_text_body: str) -> dict:
    """Signal 10: Unambiguous prompt-injection HARD tells.

    Any match → HARD signal PROMPT_INJECTION_HARD (deterministic SPAM,
    no API call). Broader/ambiguous injection phrasing is left for the AI.

    Returns:
        {
          'hard_signal': str or None,   # 'PROMPT_INJECTION_HARD' on match
          'detail': str,
        }
    """
    text = f"{subject or ''}\n{plain_text_body or ''}"

    for pat in _HARD_INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            snippet = m.group(0).replace('\n', ' ').strip()[:80]
            return {
                "hard_signal": "PROMPT_INJECTION_HARD",
                "detail": f"Hard injection pattern matched: {snippet!r}",
            }

    m = _HARD_INJECTION_IMPERATIVE.search(text)
    if m:
        snippet = m.group(0).replace('\n', ' ').strip()[:80]
        return {
            "hard_signal": "PROMPT_INJECTION_HARD",
            "detail": f"Hard injection (imperative+target) matched: {snippet!r}",
        }

    return {"hard_signal": None, "detail": ""}


def check_header_signals(headers: dict, plain_text_body: str,
                         sending_ip: str = None,
                         dnsbl_timeout: float = 3.0) -> dict:
    """Orchestrate the pre-classifier HARD signal checks.

    Only HARD signals exist now — each one auto-blocks deterministically (no AI
    call). Soft signals were removed: a non-hard, non-listed message is routed
    to the AI to judge from the full SERVER-VERIFIED authentication block and
    content, so there is no longer any soft pre-classifier context to assemble.
    ``soft_signals`` is always ``[]`` (kept for backward compatibility with
    consumers that read the key) and ``signal_details`` carries only hard-signal
    detail. ``pre_classifier_verdict`` / hard-block logic is unchanged.

    Hard signals: SPF_DKIM_BOTH_FAIL, LEAKED_AI_PROMPT (>= 2 markers),
    PROMPT_INJECTION_HARD, IP_DNSBL_MULTIPLE.
    """

    hard_signals = []
    signal_details = {}

    # Signal 1: Authentication — both SPF and DKIM fail (hard).
    s1 = check_auth_results(headers)
    if s1["signal"] == "SPF_DKIM_BOTH_FAIL":
        hard_signals.append(s1["signal"])
        signal_details[s1["signal"]] = s1["detail"]

    # Signal 9: Leaked AI generation-prompt content — >= 2 distinct markers (hard).
    s9 = check_leaked_ai_prompt(headers.get("Subject", ""), plain_text_body)
    if s9["hard_signal"]:
        hard_signals.append(s9["hard_signal"])
        signal_details[s9["hard_signal"]] = s9["detail"]

    # Signal 10: Unambiguous TRUE prompt-injection hard tells (hard).
    s10 = check_hard_prompt_injection(headers.get("Subject", ""), plain_text_body)
    if s10["hard_signal"]:
        hard_signals.append(s10["hard_signal"])
        signal_details[s10["hard_signal"]] = s10["detail"]

    # Signal 7: IP reputation — listed on 2+ DNSBLs (hard; requires sending_ip,
    # may be slow).
    if sending_ip:
        s7 = check_ip_reputation(sending_ip, timeout=dnsbl_timeout)
        if s7["signal"] == "IP_DNSBL_MULTIPLE":
            hard_signals.append(s7["signal"])
            signal_details[s7["signal"]] = s7["detail"]

    # Compute verdict.
    # F2 (Matt-locked): ONLY hard signals may auto-junk. Everything else is
    # routed to the AI for a real decision (no soft auto-junk ever).
    verdict = None
    confidence = 0.0
    if hard_signals:
        verdict = "SPAM"
        confidence = 0.95

    return {
        "hard_signals": hard_signals,
        "soft_signals": [],
        "signal_details": signal_details,
        "pre_classifier_verdict": verdict,
        "pre_classifier_confidence": confidence,
    }


def process_blacklist_entry(eml_bytes: bytes, subfolder_type: str,
                            skip_names_set: set) -> dict:
    """Process a raw .eml to determine what to add to the blacklist.

    Args:
        eml_bytes: raw email bytes
        subfolder_type: one of "both", "name-only", "address-only"
        skip_names_set: set of lowercase display names to never auto-extract

    Returns dict with:
        address: str or None — to add to blacklist.addresses
        display_name: str or None — to add to blacklist.display_names
        skipped_name: str or None — display name that was skipped
        warning: str or None — warning message if any
        original_from: str — raw From: header for logging
    """
    result = {
        "address": None,
        "display_name": None,
        "skipped_name": None,
        "warning": None,
        "original_from": "",
    }

    try:
        msg = email.message_from_bytes(eml_bytes, policy=email.policy.compat32)
    except Exception as e:
        result["warning"] = f"Failed to parse email: {e}"
        return result

    from_header = str(msg.get("From", "") or "")
    result["original_from"] = from_header

    parsed = parse_from_address(from_header)
    addr = parsed.get("address")
    display_name = parsed.get("display_name")

    if not addr and not display_name:
        result["warning"] = f"Could not extract address or display name from: {from_header!r}"
        return result

    # Apply subfolder type rules
    if subfolder_type == "both":
        if addr:
            result["address"] = addr
        if display_name:
            # Check skip_names
            if display_name.strip().lower() in skip_names_set:
                result["skipped_name"] = display_name
                result["warning"] = (
                    f"Display name '{display_name}' is too generic (in skip_names.txt); "
                    f"only the address was blacklisted."
                )
            else:
                result["display_name"] = display_name
    elif subfolder_type == "name-only":
        if display_name:
            if display_name.strip().lower() in skip_names_set:
                result["skipped_name"] = display_name
                result["warning"] = (
                    f"Display name '{display_name}' is too generic; nothing blacklisted."
                )
            else:
                result["display_name"] = display_name
        else:
            result["warning"] = "No display name found in email; nothing to blacklist (name-only)."
    elif subfolder_type == "address-only":
        if addr:
            result["address"] = addr
        else:
            result["warning"] = "No address found in email; nothing to blacklist (address-only)."
    else:
        result["warning"] = f"Unknown subfolder_type: {subfolder_type}"

    return result

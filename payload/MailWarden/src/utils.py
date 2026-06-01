#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Shared utility functions for the spam filter system.
"""

import email
import email.header
import email.policy
import html
import re
import smtplib


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
        addr = angle_match.group(2).strip().lower()
        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', addr):
            result["address"] = addr
            result["display_name"] = display_name if display_name else None
        return result

    # No angle brackets — try the whole string as a bare address
    bare = header_value.strip().strip('"').strip("'").strip()
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', bare):
        result["address"] = bare.lower()

    return result


def extract_domain(email_address: str) -> str:
    """Extract the @domain.com portion from an email address.

    Returns the lowercase domain with @ prefix, or None if invalid.
    """
    if not email_address or "@" not in email_address:
        return None
    domain = "@" + email_address.split("@", 1)[1].strip().lower()
    return domain


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

# Legitimate ESPs where domain mismatches are expected and benign.
# Used by reply-to and message-id signals.
LEGITIMATE_ESPS = {
    "mailchimp.com", "mcsv.net", "mcdlv.net",
    "sendgrid.net", "sendgrid.com",
    "amazonses.com", "ses-us-east-1.amazonses.com",
    "constantcontact.com", "ccsend.com",
    "campaignmonitor.com", "createsend.com", "cmail1.com", "cmail19.com",
    "klaviyo.com", "klaviyomail.com",
    "mailgun.org", "mailgun.net",
    "postmarkapp.com", "pm-bounces.com",
    "sparkpostmail.com",
    "list-manage.com",
    "sendinblue.com", "brevo.com",
}


def _domain_in_esp(domain: str) -> bool:
    """Return True if domain matches or is a subdomain of a known ESP."""
    if not domain:
        return False
    domain = domain.lower().lstrip("@")
    for esp in LEGITIMATE_ESPS:
        if domain == esp or domain.endswith("." + esp):
            return True
    return False


def check_auth_results(headers: dict) -> dict:
    """Signal 1: SPF/DKIM/DMARC failures.
    Hard: both SPF and DKIM fail. Soft: single failure.
    Returns {'signal': None | 'SPF_DKIM_BOTH_FAIL' | 'SPF_OR_DKIM_FAIL', 'detail': str}."""
    auth_results = headers.get("Authentication-Results", "") or ""
    received_spf = headers.get("Received-SPF", "") or ""
    combined = (auth_results + " " + received_spf).lower()

    if not combined.strip():
        return {"signal": None, "detail": ""}

    spf_fail = bool(re.search(r'spf=(fail|softfail|permerror)\b', combined))
    dkim_fail = bool(re.search(r'dkim=(fail|permerror|policy)\b', combined))

    if spf_fail and dkim_fail:
        return {"signal": "SPF_DKIM_BOTH_FAIL", "detail": "Both SPF and DKIM failed"}
    if spf_fail:
        return {"signal": "SPF_OR_DKIM_FAIL", "detail": "SPF failed"}
    if dkim_fail:
        return {"signal": "SPF_OR_DKIM_FAIL", "detail": "DKIM failed"}
    return {"signal": None, "detail": ""}


def summarize_authentication(headers: dict, from_domain: str = "") -> dict:
    """Summarize SPF/DKIM/DMARC results + the cryptographically VERIFIED sending
    domain(s) for the AI classifier (F3). HOST-AGNOSTIC.

    Parses the RFC 8601 ``Authentication-Results`` header — emitted by virtually
    every modern mail provider (Gmail, Outlook/Office365, Yahoo/AOL, Proofpoint,
    cPanel/Exim, Zoho, Fastmail, …) — plus its ARC-sealed variant
    ``ARC-Authentication-Results`` (present when mail is forwarded/relayed, e.g.
    through Microsoft) and the standalone ``Received-SPF`` header. It reads only
    STANDARD tokens (``spf=``, ``dkim=``, ``dmarc=``, ``header.from=``,
    ``header.d=``, ``header.i=@``, ``smtp.mailfrom=``), never any host-specific
    format, so it is independent of the user's email provider. Opaque
    provider-private blobs (X-YMailISG, X-Spam-*, etc.) are ignored.

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
    auth = "  ".join(p for p in (
        str(headers.get("Authentication-Results", "") or ""),
        str(headers.get("ARC-Authentication-Results", "") or ""),
    ) if p)
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

    authenticated = set()

    # DKIM-authenticated domains — only when DKIM passed.
    if dkim == "pass":
        for m in re.finditer(r'header\.(?:i\s*=\s*@?|d\s*=\s*)([a-z0-9.\-]+)',
                             auth, re.IGNORECASE):
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

    # Unverified DKIM-Signature d= CLAIM — never authenticated unless DKIM passed.
    claimed_dkim = ""
    m = re.search(r'\bd\s*=\s*([a-z0-9.\-]+)', dkim_sig, re.IGNORECASE)
    if m:
        claimed_dkim = m.group(1).lower().rstrip(".")
        if dkim == "pass":
            authenticated.add(claimed_dkim)

    return {
        "spf": spf or "none",
        "dkim": dkim or "none",
        "dmarc": dmarc or "none",
        "dmarc_from": dmarc_from,
        "spf_mailfrom": spf_mailfrom,
        "claimed_dkim_domain": claimed_dkim,
        "authenticated_domains": sorted(authenticated),
        "from_domain": (from_domain or "").lower().lstrip("@").rstrip("."),
    }


def check_spam_score(headers: dict) -> dict:
    """Signal 2: SpamAssassin verdict (Bluehost / cPanel).

    IMPORTANT (F1): the ``X-Spam-Score`` header is the SpamAssassin score
    multiplied by TEN — a clean score of 1.6 is stamped as ``X-Spam-Score: 16``.
    Reading that integer as the score made clean mail look like 16 and was a
    primary false-positive source. We now IGNORE ``X-Spam-Score`` entirely and
    read the REAL decimal from ``X-Spam-Status`` (``score=N.N``) plus the verdict
    from ``X-Spam-Flag`` / ``X-Spam-Status``.

    SpamAssassin runs UPSTREAM of MailWarden, so genuinely spammy mail is
    normally moved out before we ever see it — nearly everything we evaluate is
    ``Flag: NO`` with a low score. Therefore only a genuinely HIGH verdict counts
    as spam evidence (and even then it is a SOFT signal that routes to the AI; it
    never auto-junks):
      - ``X-Spam-Flag: YES``, or
      - ``X-Spam-Status`` verdict ``Yes``, or
      - real decimal score >= 5.0 (SpamAssassin's usual spam threshold; covers
        'tag-only' configs that still deliver flagged mail to the inbox).
    The normal low range is treated as NO signal (mild evidence of legitimacy,
    not spam). AOL/Yahoo do not stamp ``X-Spam-*`` at all → no signal there.
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


def check_reply_to_mismatch(headers: dict) -> dict:
    """Signal 3: Reply-To domain differs from From domain.
    Skip if Reply-To absent. Skip if either is a known ESP."""
    reply_to = headers.get("Reply-To", "") or ""
    from_hdr = headers.get("From", "") or ""

    if not reply_to.strip():
        return {"signal": None, "detail": ""}

    rt_parsed = parse_from_address(reply_to)
    from_parsed = parse_from_address(from_hdr)
    rt_addr = rt_parsed.get("address")
    from_addr = from_parsed.get("address")

    if not rt_addr or not from_addr:
        return {"signal": None, "detail": ""}

    rt_domain = rt_addr.split("@", 1)[1] if "@" in rt_addr else ""
    from_domain = from_addr.split("@", 1)[1] if "@" in from_addr else ""

    if rt_domain == from_domain:
        return {"signal": None, "detail": ""}
    if _domain_in_esp(rt_domain) or _domain_in_esp(from_domain):
        return {"signal": None, "detail": ""}

    return {"signal": "REPLY_TO_MISMATCH",
            "detail": f"Reply-To domain '{rt_domain}' differs from From domain '{from_domain}'"}


def check_list_unsubscribe(headers: dict, plain_text_body: str = "") -> dict:
    """Signal 4: List-Unsubscribe on transactional email.
    Fires if List-Unsubscribe present AND subject/from contains transactional language."""
    list_unsub = headers.get("List-Unsubscribe", "") or ""
    if not list_unsub.strip():
        return {"signal": None, "detail": ""}

    subject = (headers.get("Subject", "") or "").lower()
    from_hdr = (headers.get("From", "") or "").lower()
    combined = subject + " " + from_hdr

    transactional_terms = [
        "delivery", "shipment", "shipped", "package", "parcel",
        "tracking", "arriving",
        "account", "membership", "plan",
        "points", "rewards", "claim", "prize",
        "generator", "kit", "giveaway",
        "invoice", "receipt", "order confirmation",
    ]
    hits = [t for t in transactional_terms if t in combined]
    if hits:
        return {"signal": "LIST_UNSUB_TRANSACT",
                "detail": f"List-Unsubscribe on transactional email (terms: {', '.join(hits[:3])})"}
    return {"signal": None, "detail": ""}


def check_message_id_domain(headers: dict) -> dict:
    """Signal 5: Message-ID domain differs from From domain.
    Skip if either is a known ESP."""
    msg_id = headers.get("Message-ID", "") or ""
    from_hdr = headers.get("From", "") or ""

    if not msg_id.strip() or not from_hdr.strip():
        return {"signal": None, "detail": ""}

    # Extract domain from Message-ID: <stuff@domain>
    mid_match = re.search(r'<[^@>]+@([^>]+)>', msg_id)
    if not mid_match:
        return {"signal": None, "detail": ""}
    mid_domain = mid_match.group(1).strip().lower()

    from_parsed = parse_from_address(from_hdr)
    from_addr = from_parsed.get("address")
    if not from_addr:
        return {"signal": None, "detail": ""}
    from_domain = from_addr.split("@", 1)[1] if "@" in from_addr else ""

    if mid_domain == from_domain:
        return {"signal": None, "detail": ""}

    # Allow subdomain relationships
    if mid_domain.endswith("." + from_domain) or from_domain.endswith("." + mid_domain):
        return {"signal": None, "detail": ""}

    if _domain_in_esp(mid_domain) or _domain_in_esp(from_domain):
        return {"signal": None, "detail": ""}

    return {"signal": "MESSAGE_ID_MISMATCH",
            "detail": f"Message-ID domain '{mid_domain}' differs from From domain '{from_domain}'"}


def check_plain_text_quality(plain_text_body: str) -> dict:
    """Signal 6: Plain text body is absent, empty, very short, CSS-only, or obfuscated."""
    if plain_text_body is None:
        return {"signal": "DEGRADED_PLAIN_TEXT", "detail": "Plain text part absent"}

    body = str(plain_text_body).strip()
    if not body:
        return {"signal": "DEGRADED_PLAIN_TEXT", "detail": "Plain text empty"}

    # Strip whitespace for length check
    stripped = re.sub(r'\s+', '', body)
    if len(stripped) < 50:
        return {"signal": "DEGRADED_PLAIN_TEXT",
                "detail": f"Plain text very short ({len(stripped)} chars)"}

    # CSS detection: count class-like patterns and CSS punctuation
    css_chars = len(re.findall(r'[{};:]', body))
    dot_class = len(re.findall(r'\.[a-zA-Z_][\w-]*\s*\{', body))
    if len(body) > 0:
        css_ratio = (css_chars + dot_class * 3) / len(body)
        if css_ratio > 0.3 and dot_class >= 2:
            return {"signal": "DEGRADED_PLAIN_TEXT",
                    "detail": f"Plain text appears to be CSS only (ratio {css_ratio:.2f})"}

    # Obfuscation: >50% non-alphanumeric/whitespace
    non_word = len(re.findall(r'[^\w\s]', body))
    if len(body) > 0 and (non_word / len(body)) > 0.5:
        return {"signal": "DEGRADED_PLAIN_TEXT",
                "detail": f"Plain text appears obfuscated ({non_word}/{len(body)} non-word chars)"}

    return {"signal": None, "detail": ""}


def _extract_sending_ip(received_headers) -> str:
    """Extract the first external sending IP from Received headers.
    Skips localhost and private IPs."""
    if not received_headers:
        return None
    if isinstance(received_headers, str):
        received_headers = [received_headers]

    # Start from the last Received header (earliest in chain) and work up
    for hdr in reversed(received_headers):
        hdr_str = str(hdr)
        # Find IPv4 addresses
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', hdr_str)
        for ip in ips:
            parts = ip.split(".")
            try:
                p = [int(x) for x in parts]
            except ValueError:
                continue
            # Skip private/reserved ranges
            if p[0] == 10:
                continue
            if p[0] == 127:
                continue
            if p[0] == 172 and 16 <= p[1] <= 31:
                continue
            if p[0] == 192 and p[1] == 168:
                continue
            if p[0] == 0:
                continue
            return ip
    return None


def check_ip_reputation(sending_ip: str, timeout: float = 3.0) -> dict:
    """Signal 7: DNSBL lookup on sending IP.
    Hard: listed on 2+ blocklists. Soft: listed on 1."""
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

    parts = sending_ip.split(".")
    if len(parts) != 4:
        return {"signal": None, "detail": "", "hits": []}
    reversed_ip = ".".join(reversed(parts))

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
    if len(hits) == 1:
        return {"signal": "IP_DNSBL_SINGLE",
                "detail": f"IP {sending_ip} listed on: {hits[0]}",
                "hits": hits}
    return {"signal": None, "detail": "", "hits": []}


# ---------------------------------------------------------------------------
# Pre-classifier signal: prompt-injection attempt detector
# (c) 2026 STR Solutions, LLC. All rights reserved.
# ---------------------------------------------------------------------------

# High-precision patterns for prompt-injection attempts in email content.
# All patterns are case-insensitive. Kept narrow to minimise false positives
# on legitimate AI-related newsletters or discussion email.
#
# Calibration intent:
#   Soft-signal threshold is 3. Injection fires TWO soft signals
#   (PROMPT_INJECTION_ATTEMPT + PROMPT_INJECTION_ATTEMPT_BOOST) so that:
#     injection alone        = 2 signals  <  3  (no verdict — passes through)
#     injection + 1 other    = 3 signals  >= 3  (SPAM verdict)
#   A legitimate email that merely mentions AI topics uses none of these
#   precise imperative/role-switching phrases and will score 0 from this check.
_INJECTION_PATTERNS = [
    # Classic "ignore previous instructions" family
    re.compile(
        r'ignore\s+(all\s+|the\s+)?(previous|prior|above)\s+instructions?',
        re.IGNORECASE),
    re.compile(
        r'disregard\s+(your|all|previous|prior|above)\s+instructions?',
        re.IGNORECASE),
    re.compile(
        r'forget\s+(all\s+)?(previous|prior|above|your)\s+instructions?',
        re.IGNORECASE),
    # Role/persona override
    re.compile(r'\byou\s+are\s+now\b', re.IGNORECASE),
    re.compile(r'\bact\s+as\b', re.IGNORECASE),
    re.compile(r'\bpretend\s+(you\s+are|to\s+be)\b', re.IGNORECASE),
    # System-layer references — high-signal in untrusted email
    re.compile(r'\bsystem\s+prompt\b', re.IGNORECASE),
    re.compile(r'\bdeveloper\s+message\b', re.IGNORECASE),
    re.compile(r'\bsystem\s+message\b', re.IGNORECASE),
    # Conversation-role injections: lines that start with Human:/Assistant:/System:
    re.compile(r'(?:^|\n)\s*(?:human|assistant|system)\s*:', re.IGNORECASE),
    # Attempts to reveal or override the prompt
    re.compile(r'\breveal\s+(your|the)\s+(system\s+)?prompt\b', re.IGNORECASE),
    re.compile(r'\boverride\s+(your\s+)?(instructions?|directives?|rules?)\b',
               re.IGNORECASE),
    re.compile(r'\bnew\s+instructions?\s*:', re.IGNORECASE),
    # Literal injected delimiter tags (closing the untrusted_email wrapper)
    re.compile(r'</?\s*untrusted_email\s*>', re.IGNORECASE),
]


def check_prompt_injection(subject: str, plain_text_body: str) -> dict:
    """Signal 8: Prompt-injection attempt in subject or body.

    Scans the decoded subject line and plain-text body for high-precision
    prompt-injection patterns. Returns two parallel soft signals when a
    match is found so that the pair counts as 2 of the 3 soft signals
    required for a SPAM verdict — satisfying the calibration constraint
    that injection alone cannot decide spam but injection + one other
    signal can.

    Returns:
        {
          'signals': list of 0 or 2 signal name strings,
          'detail': str,
        }
    """
    text = f"{subject or ''}\n{plain_text_body or ''}"
    for pat in _INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            snippet = m.group(0).replace('\n', ' ').strip()[:80]
            detail = f"Prompt-injection pattern matched: {snippet!r}"
            return {
                "signals": [
                    "PROMPT_INJECTION_ATTEMPT",
                    "PROMPT_INJECTION_ATTEMPT_BOOST",
                ],
                "detail": detail,
            }
    return {"signals": [], "detail": ""}


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
#   exactly 1 marker → ONE soft signal (contributes toward the 3-soft
#      threshold but is not decisive alone)
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
    """Signal 9: Leaked AI generation-prompt content in subject or body.

    Counts how many DISTINCT markers from _LEAKED_AI_PROMPT_MARKERS appear
    (case-insensitive) in the combined subject + body text.

    Returns:
        {
          'hard_signal': str or None,   # 'LEAKED_AI_PROMPT' if >= 2 markers
          'soft_signals': list[str],    # ['LEAKED_AI_PROMPT'] if exactly 1 marker
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
            "soft_signals": [],
            "detail": (
                f"Leaked AI generation prompt detected: {count} distinct markers "
                f"({', '.join(repr(f) for f in found[:4])}{'...' if count > 4 else ''})"
            ),
            "marker_count": count,
        }
    if count == 1:
        return {
            "hard_signal": None,
            "soft_signals": ["LEAKED_AI_PROMPT"],
            "detail": f"Possible leaked AI prompt: marker {found[0]!r} found",
            "marker_count": count,
        }
    return {"hard_signal": None, "soft_signals": [], "detail": "", "marker_count": 0}


# ---------------------------------------------------------------------------
# Pre-classifier signal: TRUE prompt-injection HARD tells (ITEM 5)
# (c) 2026 STR Solutions, LLC. All rights reserved.
# ---------------------------------------------------------------------------
#
# Only patterns with essentially zero legitimate occurrence are placed here.
# Broader/ambiguous patterns stay as the existing soft PROMPT_INJECTION_ATTEMPT.
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
    no API call). Keeps the existing soft check_prompt_injection() intact
    for the broader/ambiguous patterns.

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
    """Orchestrate all pre-classifier signal checks.
    Returns a summary dict with hard_signals, soft_signals, signal_details,
    pre_classifier_verdict (None or 'SPAM'), and pre_classifier_confidence."""

    hard_signals = []
    soft_signals = []
    signal_details = {}

    # Signal 1: Authentication
    s1 = check_auth_results(headers)
    if s1["signal"] == "SPF_DKIM_BOTH_FAIL":
        hard_signals.append(s1["signal"])
        signal_details[s1["signal"]] = s1["detail"]
    elif s1["signal"] == "SPF_OR_DKIM_FAIL":
        soft_signals.append(s1["signal"])
        signal_details[s1["signal"]] = s1["detail"]

    # Signal 2: Spam score
    s2 = check_spam_score(headers)
    if s2["signal"]:
        soft_signals.append(s2["signal"])
        signal_details[s2["signal"]] = s2["detail"]

    # Signal 3: Reply-To mismatch
    s3 = check_reply_to_mismatch(headers)
    if s3["signal"]:
        soft_signals.append(s3["signal"])
        signal_details[s3["signal"]] = s3["detail"]

    # Signal 4: List-Unsubscribe on transactional
    s4 = check_list_unsubscribe(headers, plain_text_body)
    if s4["signal"]:
        soft_signals.append(s4["signal"])
        signal_details[s4["signal"]] = s4["detail"]

    # Signal 5: Message-ID mismatch
    s5 = check_message_id_domain(headers)
    if s5["signal"]:
        soft_signals.append(s5["signal"])
        signal_details[s5["signal"]] = s5["detail"]

    # Signal 6: Plain text quality
    s6 = check_plain_text_quality(plain_text_body)
    if s6["signal"]:
        soft_signals.append(s6["signal"])
        signal_details[s6["signal"]] = s6["detail"]

    # Signal 8: Prompt-injection attempt in subject or body.
    # Fires two soft signals together so that injection alone < threshold
    # (2 < 3) but injection + one other soft signal reaches the verdict
    # threshold (3 >= 3). See check_prompt_injection() for calibration notes.
    s8 = check_prompt_injection(headers.get("Subject", ""), plain_text_body)
    if s8["signals"]:
        for sig_name in s8["signals"]:
            soft_signals.append(sig_name)
            signal_details[sig_name] = s8["detail"]

    # Signal 9: Leaked AI generation-prompt content.
    # >= 2 distinct markers → HARD signal LEAKED_AI_PROMPT (no API).
    # exactly 1 marker → one soft signal (contributes toward threshold).
    s9 = check_leaked_ai_prompt(headers.get("Subject", ""), plain_text_body)
    if s9["hard_signal"]:
        hard_signals.append(s9["hard_signal"])
        signal_details[s9["hard_signal"]] = s9["detail"]
    elif s9["soft_signals"]:
        for sig_name in s9["soft_signals"]:
            soft_signals.append(sig_name)
            signal_details[sig_name] = s9["detail"]

    # Signal 10: Unambiguous TRUE prompt-injection hard tells.
    # Any match → HARD signal PROMPT_INJECTION_HARD (no API).
    # Leaves existing soft check_prompt_injection() for broader patterns.
    s10 = check_hard_prompt_injection(headers.get("Subject", ""), plain_text_body)
    if s10["hard_signal"]:
        hard_signals.append(s10["hard_signal"])
        signal_details[s10["hard_signal"]] = s10["detail"]

    # Signal 7: IP reputation (requires sending_ip; may be slow)
    if sending_ip:
        s7 = check_ip_reputation(sending_ip, timeout=dnsbl_timeout)
        if s7["signal"] == "IP_DNSBL_MULTIPLE":
            hard_signals.append(s7["signal"])
            signal_details[s7["signal"]] = s7["detail"]
        elif s7["signal"] == "IP_DNSBL_SINGLE":
            soft_signals.append(s7["signal"])
            signal_details[s7["signal"]] = s7["detail"]

    # Compute verdict.
    # F2 (Matt-locked): ONLY hard signals may auto-junk. A stack of soft signals
    # — no matter how many — is NEVER auto-junked; it is routed to the AI as
    # context for a real decision. Previously >=3 soft auto-junked at 0.88, which
    # silently junked legitimate bulk/transactional mail (e.g. Dashlane) with no
    # AI call. The soft_signals list is still returned so the caller can pass it
    # to the classifier as non-dispositive context.
    verdict = None
    confidence = 0.0
    if hard_signals:
        verdict = "SPAM"
        confidence = 0.95

    return {
        "hard_signals": hard_signals,
        "soft_signals": soft_signals,
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

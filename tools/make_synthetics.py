#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Generate the synthetic eval fixtures — 16 hand-built .eml files with ground
truth by construction. DEV-ONLY (tools/ is outside the installer payload).

These fixtures contain NO real mail and NO private data; every sender,
recipient, host, and body is invented. They cover the phish classes the real
corpus under-represents (lookalike domains, display-name spoofs, own-domain-
authenticated spam, DKIM-signed-but-misaligned phish) plus the authenticated+
brand-matched LEGIT path that real harvested mail never exercises.

DKIM: four fixtures carry a REAL, verifiable DKIM signature made with the
throwaway test keypair embedded below. The keypair exists only for these
fixtures — it signs nothing else and its "DNS record" is served exclusively
through the ``dkim_test_dnsfunc`` seam (utils.verify_dkim_locally's
``_dnsfunc`` parameter), so no live DNS is ever consulted in tests.

Usage:
  tests/.venv/bin/python tools/make_synthetics.py            # write to tools/eval_synthetic/
  tests/.venv/bin/python tools/make_synthetics.py --out DIR  # write elsewhere

Output is deterministic (fixed dates, fixed Message-IDs, deterministic RSA
PKCS#1 v1.5 signatures), so regeneration produces identical bytes.

IMPORTANT: these files enter the Desktop benchmark corpus ONLY after Matt
approves the label list. This script never touches ~/Desktop.
"""
import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "tools" / "eval_synthetic"

# ---------------------------------------------------------------------------
# Throwaway DKIM test keypair (generated 2026-07-02 solely for these fixtures;
# never used to sign real mail; the private half being public is the point —
# ground truth by construction, verified only through dkim_test_dnsfunc).
# ---------------------------------------------------------------------------

TEST_DKIM_SELECTOR = "eval2026"

TEST_DKIM_PRIVATE_KEY_PEM = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtZbzsyJTeUOD0+PXnO3ZQqbtbVMJuR5Rf5N5Y4WYx59xbk69
IU883lxk6TSSvIcDcNri0udH055wQfB+jvYKwodzLzFHEyFVrm3ZnJLB0hqdxM6Q
RqsTv/HL5U8Shm/VpazzchJ/nYQwX9kEsPyt1Y0wMh+CFkTHAn8ZEb/05jmSL0aH
fNNKq+KNscOpV6/xcvr5iOQwS9808yqgqsRKcTqkdhsSk9dgdwwPDE7Y0OLhIPjx
WhJ9w+uepf8agojODN6kxuqE+RiCCjJ7/kU+ZyL7c2ggOQPJ5OGbggoj9ZUfUsHh
RLhz2VgV2yhgRcfDgwKhADQ2yswN0FOaHHt2vwIDAQABAoIBAEa0K1hE1caiBJrE
nIe0ToM2trx5+A+1n9ryI3IeKwIS8VoXW2m0TglwZTQuLbItSagv+eBPgDaD+saZ
6tUkNMVQcwddgwSOVquvhusBc2koxuRB34g8hViXv6Gd26MvuTqkcDeqvzioJyOy
vrJg+BhtvGXPwdmE1w4ASdUQ7jyTZP8JDxlS7mzAP44bqgCb353Q56Ur7VdcCoan
rftFRxk1rZZIuqM2ntvZ5/pfTljgY8bnaqATjwj+1fuBHn9KQAkJODxP7mgY3ArY
L3H+grsBJ99S7vONAAV2nCqcA1L/ettiuCuPg1R2u4xXd6HNR7VnTx5bypaaEYQh
4oEQmF0CgYEA/EtRe4fNpWOgAC4mMfEuDpgt1O/Q5BImkD7NTWfzAc3Wql79LYah
CrRX0QL7MNJ9h3gVLs67xRvrMfs17UirD8T4qs0UaLTQQOvensGpOeH9QXuEoQih
AAyOJebwcJZC+Oy9MCzfGr/9TQ/Ffup91jb2J3xIS1MVHdHEkxXS2FUCgYEAuEHE
3C3nslZnYN8nJNyYGwI+RJXURkdH+K7np5fhCSs4ctwg5nOifiqCzgHzPkqQYeNo
BVg6KcUulqYmXzpj8UhIM0Z3dpUevoP6V8KC62YkwnIicmsCo0vRH4GWHL3nFNaY
aYouPiMrrrRkWa05RKWP4L8O26CuF8FoWfgD9sMCgYEAtoL+FTEu8YBalQbNlr90
pBYuwaYjJXqD70GfX2ndf+aabnF9Edwc0BOam5deg/kh2khiepQPfg4uXN/wKRGy
vhuuEFF/fCehp/V5/Lr4Yuk7Po3OanhFkDWE96JTOf9Zv53zVtB/LWjKI19PbfrQ
wZDNDc94tRULZ6ECZa0Z9GkCgYB96PONQhFCXKjoGZW2KsgGLNJAK+KS48LavSqv
66lrio1Yb/RLhllTvdkEzXBa8LkZKzy56kBUqtnbOE6gZFZHWw17fHvGHMCVj7pS
nii4k2QrO7MuXNHApN6SmQrrORnfs4UTGcnfzEjdaYfpf+XScxCOlACjNHnC4fdd
A44x4QKBgC+uadbuXEJCTMNcRNA7fieVaoplHpyjTFEDSHqpWf+5q2iCLmNaXrDP
plN/hGDQ1j3zCfD4CH10r+53a1HLKeBm4K/aq9TPIPJNLy6CwstX5z/zg64PWoDl
mHg6LBTEP38iHBBUF79vEgV6w4DcTLwN2Ju6i7kC4LXXpXqa6xXP
-----END RSA PRIVATE KEY-----
"""

TEST_DKIM_PUBKEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZbzsyJTeUOD0+PXnO3ZQqbtbVMJ"
    "uR5Rf5N5Y4WYx59xbk69IU883lxk6TSSvIcDcNri0udH055wQfB+jvYKwodzLzFHEyFVrm3Z"
    "nJLB0hqdxM6QRqsTv/HL5U8Shm/VpazzchJ/nYQwX9kEsPyt1Y0wMh+CFkTHAn8ZEb/05jmS"
    "L0aHfNNKq+KNscOpV6/xcvr5iOQwS9808yqgqsRKcTqkdhsSk9dgdwwPDE7Y0OLhIPjxWhJ9"
    "w+uepf8agojODN6kxuqE+RiCCjJ7/kU+ZyL7c2ggOQPJ5OGbggoj9ZUfUsHhRLhz2VgV2yhg"
    "RcfDgwKhADQ2yswN0FOaHHt2vwIDAQAB"
)

TEST_DKIM_TXT = ("v=DKIM1; k=rsa; p=" + TEST_DKIM_PUBKEY_B64).encode("ascii")


def dkim_test_dnsfunc(name, timeout=5):
    """dnsfunc seam for utils.verify_dkim_locally: serves the test public key
    for ANY domain queried under the test selector, None otherwise. Never
    touches the network. (Deliberately NOT named test_* — pytest would try to
    collect it as a test when imported into a test module.)"""
    key = name.decode("utf-8", "replace") if isinstance(
        name, (bytes, bytearray)) else str(name)
    if key.rstrip(".").startswith(TEST_DKIM_SELECTOR + "._domainkey."):
        return TEST_DKIM_TXT
    return None


# ---------------------------------------------------------------------------
# Assembly helpers
# ---------------------------------------------------------------------------

RECIPIENT = "mrosen@baycrestmail.com"          # invented recipient
MX_HOST = "mx4.baycrestmail.com"               # invented receiving host


def _eml(headers, body):
    """Assemble headers (list of (name, value)) + body into CRLF .eml bytes."""
    lines = [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")


def _received(helo, ip, ts):
    """One realistic folded Received header value. The ESMTPS id is a
    DETERMINISTIC digest of the helo (not hash(), which is per-process
    randomized) so regeneration is byte-identical on any machine."""
    import hashlib
    n = int(hashlib.sha256(helo.encode("utf-8")).hexdigest(), 16) % 90000 + 10000
    return (f"from {helo} ({helo} [{ip}])\r\n"
            f"\tby {MX_HOST} with ESMTPS id A{n};\r\n"
            f"\t{ts}")


# Frozen DKIM signing timestamp: 2026-07-01 00:00:00 UTC. dkimpy hardcodes the
# signature's t= tag to int(time.time()) with no override in dkim.sign (its
# timestamp= seam belongs to the ARC sealer only), and t= sits INSIDE the
# signed data — so a live clock changes b= on every run. Freezing it makes the
# four signed fixtures byte-reproducible. The value postdates every fixture's
# Date header (latest: 30 Jun 2026 15:22 -0400), so t= stays plausible; t= is
# informational in verification (only x= expiry is enforced).
_DKIM_SIGN_EPOCH = 1782864000


def _dkim_sign(raw, domain):
    """Prepend a real DKIM-Signature over from/to/subject/date/message-id,
    signed with the embedded test key. Deterministic: RSA PKCS#1 v1.5 is
    deterministic, and time.time is frozen to _DKIM_SIGN_EPOCH for exactly
    the duration of the dkim.sign call (restored in a finally) so the t= tag
    — and therefore b= — is identical on any machine at any time."""
    import dkim
    import time
    real_time = time.time
    time.time = lambda: _DKIM_SIGN_EPOCH
    try:
        sig = dkim.sign(
            raw,
            TEST_DKIM_SELECTOR.encode("ascii"),
            domain.encode("ascii"),
            TEST_DKIM_PRIVATE_KEY_PEM,
            include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
            canonicalize=(b"relaxed", b"relaxed"),
        )
    finally:
        time.time = real_time
    return sig + raw


# ---------------------------------------------------------------------------
# The 16 fixtures
# ---------------------------------------------------------------------------

def _f01():
    return _eml([
        ("Return-Path", "<service@paypa1-secure.com>"),
        ("Received", _received("relay2.paypa1-secure.com", "185.243.112.44",
                               "Mon, 15 Jun 2026 09:14:22 -0400")),
        ("Received", _received("vps-190412.hostbargain.net", "185.243.112.44",
                               "Mon, 15 Jun 2026 09:14:20 -0400")),
        ("From", "PayPal Service <service@paypa1-secure.com>"),
        ("To", RECIPIENT),
        ("Subject", "Your account access has been limited - Case ID PP-4471902"),
        ("Date", "Mon, 15 Jun 2026 09:14:19 -0400"),
        ("Message-ID", "<20260615091419.7F2A1@paypa1-secure.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Dear Customer,\r\n\r\n"
        "We noticed unusual activity in your account. Your access has been\r\n"
        "limited until you confirm your information.\r\n\r\n"
        "Confirm now: http://paypa1-secure.com/webapps/limit/resolve\r\n\r\n"
        "If you don't confirm within 24 hours your account will be suspended.\r\n\r\n"
        "PayPal Customer Service\r\n")


def _f02():
    return _eml([
        ("Return-Path", "<security@xn--pypal-4ve.com>"),
        ("Received", _received("mail.xn--pypal-4ve.com", "91.219.237.101",
                               "Tue, 16 Jun 2026 03:41:07 -0400")),
        ("From", "Account Security <security@xn--pypal-4ve.com>"),
        ("To", RECIPIENT),
        ("Subject", "Action required: verify your identity"),
        ("Date", "Tue, 16 Jun 2026 03:41:05 -0400"),
        ("Message-ID", "<9c22e7b0518@xn--pypal-4ve.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Your identity could not be verified.\r\n\r\n"
        "To avoid interruption of service, verify here within 12 hours:\r\n"
        "http://xn--pypal-4ve.com/id/verify?u=8842\r\n\r\n"
        "Security Team\r\n")


def _f03():
    return _eml([
        ("Return-Path", "<alert-noreply@mail-updates-ru.net>"),
        ("Received", _received("out12.mail-updates-ru.net", "77.91.68.203",
                               "Wed, 17 Jun 2026 22:05:44 -0400")),
        ("From", '"Apple Support" <alert-noreply@mail-updates-ru.net>'),
        ("To", RECIPIENT),
        ("Reply-To", "applecare.recovery@mail-updates-ru.net"),
        ("Subject", "Your Apple ID was used to sign in on a new device"),
        ("Date", "Wed, 17 Jun 2026 22:05:41 -0400"),
        ("Message-ID", "<AB99120C-4471-44E2@mail-updates-ru.net>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Your Apple ID (" + RECIPIENT + ") was used to sign in to iCloud on a\r\n"
        "Windows PC in Kyiv, Ukraine.\r\n\r\n"
        "If this wasn't you, your account may be compromised. Secure it now:\r\n"
        "http://mail-updates-ru.net/appleid/secure\r\n\r\n"
        "Apple Support\r\n")


def _f04():
    raw = _eml([
        ("Return-Path", "<offers@bkzvqrelay.com>"),
        ("Received", _received("smtp1.bkzvqrelay.com", "104.168.94.212",
                               "Thu, 18 Jun 2026 06:12:33 -0400")),
        ("From", "Exclusive Savings <offers@bkzvqrelay.com>"),
        ("To", RECIPIENT),
        ("Subject", "Final notice: your $100 fuel rewards card is waiting"),
        ("Date", "Thu, 18 Jun 2026 06:12:31 -0400"),
        ("Message-ID", "<bulk.20260618.44172@bkzvqrelay.com>"),
        ("List-Unsubscribe", "<http://bkzvqrelay.com/u/44172>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Congratulations! You have been selected to receive a $100 fuel\r\n"
        "rewards card. This offer expires TONIGHT.\r\n\r\n"
        "Claim yours: http://bkzvqrelay.com/claim?id=44172\r\n\r\n"
        "No purchase necessary. Unsubscribe: http://bkzvqrelay.com/u/44172\r\n")
    return _dkim_sign(raw, "bkzvqrelay.com")


def _f05():
    raw = _eml([
        ("Return-Path", "<deals@brightoffersdaily.com>"),
        ("Received", _received("mail.brightoffersdaily.com", "162.240.117.55",
                               "Fri, 19 Jun 2026 11:47:02 -0400")),
        ("From", "Bright Offers Daily <deals@brightoffersdaily.com>"),
        ("To", RECIPIENT),
        ("Subject", "You qualify for up to $5,000/month working from home"),
        ("Date", "Fri, 19 Jun 2026 11:47:00 -0400"),
        ("Message-ID", "<campaign-88123@brightoffersdaily.com>"),
        ("List-Unsubscribe", "<mailto:unsub@brightoffersdaily.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Hundreds in your area are already earning $5,000 or more every month\r\n"
        "from home with this one simple system. Spots are limited.\r\n\r\n"
        "Start today: http://brightoffersdaily.com/go/88123\r\n\r\n"
        "You are receiving this because you opted in to a partner offer.\r\n")
    return _dkim_sign(raw, "brightoffersdaily.com")


def _f06():
    raw = _eml([
        ("Return-Path", "<bounce-8812@mailblastpro.net>"),
        ("Received", _received("out3.mailblastpro.net", "192.243.59.18",
                               "Sat, 20 Jun 2026 14:20:11 -0400")),
        ("From", "PayPal Security <security@paypal.com>"),
        ("To", RECIPIENT),
        ("Subject", "Unusual login attempt blocked - confirm your details"),
        ("Date", "Sat, 20 Jun 2026 14:20:09 -0400"),
        ("Message-ID", "<blast-2201847@mailblastpro.net>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "We blocked a login attempt from an unrecognized device.\r\n\r\n"
        "Please confirm your account details to restore full access:\r\n"
        "http://mailblastpro.net/r/pp/confirm?c=2201847\r\n\r\n"
        "PayPal Security\r\n")
    # Valid signature, but d= (mailblastpro.net) does NOT align with the
    # claimed From domain (paypal.com) — signed phish, alignment fails.
    return _dkim_sign(raw, "mailblastpro.net")


def _f07():
    return _eml([
        ("Return-Path", "<alerts@amazon-account-security.com>"),
        ("Received", _received("mailer.amazon-account-security.com",
                               "23.94.180.77",
                               "Sun, 21 Jun 2026 08:33:55 -0400")),
        ("Authentication-Results",
         f"{MX_HOST};\r\n"
         "\tspf=pass (sender IP is 23.94.180.77) "
         "smtp.mailfrom=amazon-account-security.com;\r\n"
         "\tdkim=none;\r\n"
         "\tdmarc=none"),
        ("Received-SPF",
         "pass (domain of amazon-account-security.com designates "
         "23.94.180.77 as permitted sender)"),
        ("From", "Amazon <alerts@amazon-account-security.com>"),
        ("To", RECIPIENT),
        ("Subject", "Your order could not be shipped - payment declined"),
        ("Date", "Sun, 21 Jun 2026 08:33:52 -0400"),
        ("Message-ID", "<order-alert-71building@amazon-account-security.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Your recent order #114-2278119 could not be shipped because your\r\n"
        "payment method was declined.\r\n\r\n"
        "Update your payment information:\r\n"
        "http://amazon-account-security.com/gp/update-payment\r\n\r\n"
        "Amazon Customer Service\r\n")


def _f08():
    return _eml([
        ("Return-Path", "<billing@netflix-billing.com>"),
        ("Received", _received("send.netflix-billing.com", "45.155.204.66",
                               "Mon, 22 Jun 2026 19:58:30 -0400")),
        ("From", "Netflix <billing@netflix-billing.com>"),
        ("Reply-To", "recovery.desk1977@gmail.com"),
        ("To", RECIPIENT),
        ("Subject", "Payment failure: update your billing information"),
        ("Date", "Mon, 22 Jun 2026 19:58:28 -0400"),
        ("Message-ID", "<nb-99871253@netflix-billing.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Your last payment was declined and your membership is on hold.\r\n\r\n"
        "Reply to this message with your updated card number and billing zip,\r\n"
        "or update online: http://netflix-billing.com/account/restart\r\n\r\n"
        "The Netflix Team\r\n")


def _f09():
    return _eml([
        ("Return-Path", "<it-helpdesk@secure-mail-notice.com>"),
        ("Received", _received("relay.secure-mail-notice.com", "194.87.139.20",
                               "Tue, 23 Jun 2026 07:02:17 -0400")),
        ("From", "IT Helpdesk <it-helpdesk@secure-mail-notice.com>"),
        ("To", RECIPIENT),
        ("Subject", "Mailbox storage full - 3 incoming messages on hold"),
        ("Date", "Tue, 23 Jun 2026 07:02:15 -0400"),
        ("Message-ID", "<hd-20260623-8812@secure-mail-notice.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/html; charset=utf-8"),
    ],
        "<html><body>\r\n"
        "<p>Your mailbox has exceeded its storage quota. 3 incoming messages\r\n"
        "are currently on hold.</p>\r\n"
        '<p><a href="http://account-verify-center.xyz/quota/release?u='
        + RECIPIENT + '">\r\n'
        "Sign in to release pending messages</a></p>\r\n"
        "<p>Mail Administrator</p>\r\n"
        "</body></html>\r\n")


def _f10():
    return _eml([
        ("Return-Path", "<m.rosenberg.ceo@consultant-mail.com>"),
        ("Received", _received("smtp.consultant-mail.com", "196.251.85.140",
                               "Wed, 24 Jun 2026 10:16:48 -0400")),
        ("From", '"Matt Rosenberg" <m.rosenberg.ceo@consultant-mail.com>'),
        ("To", RECIPIENT),
        ("Subject", "Quick task - are you at your desk?"),
        ("Date", "Wed, 24 Jun 2026 10:16:45 -0400"),
        ("Message-ID", "<cm-4491bb2@consultant-mail.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Are you at your desk? I need you to process an urgent wire transfer\r\n"
        "for a vendor before 2pm today. I'm heading into a meeting and can't\r\n"
        "take calls - just reply here and I'll send the account details.\r\n\r\n"
        "Sent from my iPhone\r\n")


def _f11():
    return _eml([
        ("Return-Path", "<promo@rxsaverdepot.com>"),
        ("Received", _received("mta9.rxsaverdepot.com", "103.152.220.14",
                               "Thu, 25 Jun 2026 02:44:09 -0400")),
        ("X-Spam-Status",
         "Yes, score=11.2 required=5.0 tests=BAYES_99,HTML_IMAGE_ONLY_16,\r\n"
         "\tRDNS_NONE,URIBL_BLACK autolearn=spam"),
        ("X-Spam-Flag", "YES"),
        ("From", "Pharmacy Direct <promo@rxsaverdepot.com>"),
        ("To", RECIPIENT),
        ("Subject", "80% off name-brand medications - no prescription needed"),
        ("Date", "Thu, 25 Jun 2026 02:44:06 -0400"),
        ("Message-ID", "<rx-6620184@rxsaverdepot.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Save up to 80% on name-brand medications shipped overnight.\r\n"
        "No prescription required. Discreet packaging.\r\n\r\n"
        "Shop now: http://rxsaverdepot.com/catalog\r\n")


def _f12():
    return _eml([
        ("Return-Path", "<winner@prizeclaimcenter.net>"),
        ("Received", _received("out.prizeclaimcenter.net", "179.43.175.98",
                               "Fri, 26 Jun 2026 16:29:51 -0400")),
        ("From", "Rewards Center <winner@prizeclaimcenter.net>"),
        ("To", RECIPIENT),
        ("Subject", "CONGRATULATIONS! You've won a $500 Walmart gift card"),
        ("Date", "Fri, 26 Jun 2026 16:29:49 -0400"),
        ("Message-ID", "<prize-100382@prizeclaimcenter.net>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "You have been randomly selected to receive a $500 Walmart gift card!\r\n\r\n"
        "Claim within 24 hours or your prize will be forfeited:\r\n"
        "http://prizeclaimcenter.net/claim/100382\r\n\r\n"
        "Just pay $1.95 shipping and handling.\r\n")


def _f13():
    invisible = "&zwnj;" * 120
    return _eml([
        ("Return-Path", "<news@dailyhealthwire.info>"),
        ("Received", _received("m1.dailyhealthwire.info", "45.93.201.77",
                               "Sat, 27 Jun 2026 05:11:26 -0400")),
        ("From", "Daily Health Wire <news@dailyhealthwire.info>"),
        ("To", RECIPIENT),
        ("Subject", "Doctors furious over this one weird trick"),
        ("Date", "Sat, 27 Jun 2026 05:11:24 -0400"),
        ("Message-ID", "<dhw-77ela10@dailyhealthwire.info>"),
        ("List-Unsubscribe", "<http://dailyhealthwire.info/optout>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/html; charset=utf-8"),
    ],
        "<html><body>\r\n"
        "<div style=\"display:none\">" + invisible + "</div>\r\n"
        "<p>Local doctors are furious after a retired teacher discovered this\r\n"
        "one weird trick to melt belly fat overnight.</p>\r\n"
        '<p><a href="http://dailyhealthwire.info/trk/77ela10">Watch the video\r\n'
        "before it's taken down</a></p>\r\n"
        '<p><a href="http://dailyhealthwire.info/optout">Unsubscribe</a></p>\r\n'
        "</body></html>\r\n")


def _f14():
    return _eml([
        ("Return-Path", "<receipts@stripemarket.com>"),
        ("Received", _received("mail-out.stripemarket.com", "54.240.27.180",
                               "Sun, 28 Jun 2026 12:40:03 -0400")),
        ("Authentication-Results",
         f"{MX_HOST};\r\n"
         "\tspf=pass (sender IP is 54.240.27.180) "
         "smtp.mailfrom=stripemarket.com;\r\n"
         "\tdkim=pass header.d=stripemarket.com;\r\n"
         "\tdmarc=pass action=none header.from=stripemarket.com"),
        ("From", "StripeMarket Receipts <receipts@stripemarket.com>"),
        ("To", RECIPIENT),
        ("Subject", "Your receipt from Harborview Dental - $184.00"),
        ("Date", "Sun, 28 Jun 2026 12:40:01 -0400"),
        ("Message-ID", "<rcpt_1PZk2026a@stripemarket.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Receipt from Harborview Dental\r\n\r\n"
        "Amount paid: $184.00\r\n"
        "Date: June 28, 2026\r\n"
        "Payment method: Visa ending 4242\r\n\r\n"
        "Questions? Contact Harborview Dental at (555) 014-2200.\r\n")


def _f15():
    return _eml([
        ("Return-Path", "<bounces+news@nordwestoutfitters.com>"),
        ("Received", _received("o1.email.nordwestoutfitters.com",
                               "167.89.54.101",
                               "Mon, 29 Jun 2026 09:00:12 -0400")),
        ("Authentication-Results",
         f"{MX_HOST};\r\n"
         "\tspf=pass (sender IP is 167.89.54.101) "
         "smtp.mailfrom=email.nordwestoutfitters.com;\r\n"
         "\tdkim=pass header.d=nordwestoutfitters.com;\r\n"
         "\tdmarc=pass action=none header.from=nordwestoutfitters.com"),
        ("From", "NordWest Outfitters <news@nordwestoutfitters.com>"),
        ("To", RECIPIENT),
        ("Subject", "The Summer Clearance Event starts now - up to 60% off"),
        ("Date", "Mon, 29 Jun 2026 09:00:09 -0400"),
        ("Message-ID", "<nwo-sum26-991@nordwestoutfitters.com>"),
        ("List-Unsubscribe",
         "<mailto:unsubscribe@nordwestoutfitters.com>, "
         "<https://nordwestoutfitters.com/email/unsubscribe>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/html; charset=utf-8"),
    ],
        "<html><body>\r\n"
        "<h1>Summer Clearance: up to 60% off</h1>\r\n"
        "<p>Hurry - our biggest sale of the season ends Sunday! Shop hiking,\r\n"
        "camping, and paddle gear at clearance prices.</p>\r\n"
        '<p><a href="https://nordwestoutfitters.com/sale">Shop the sale</a></p>\r\n'
        '<p><a href="https://nordwestoutfitters.com/email/unsubscribe">'
        "Unsubscribe</a> | NordWest Outfitters, 4410 Cascade Ave, Portland OR</p>\r\n"
        "</body></html>\r\n")


def _f16():
    raw = _eml([
        ("Return-Path", "<receipts@harborviewdental.com>"),
        ("Received", _received("server82.sharedwebhost.com", "70.40.220.51",
                               "Tue, 30 Jun 2026 15:22:37 -0400")),
        ("From", "Harborview Dental <receipts@harborviewdental.com>"),
        ("To", RECIPIENT),
        ("Subject", "Appointment confirmed for Tuesday, July 7 at 10:30 AM"),
        ("Date", "Tue, 30 Jun 2026 15:22:35 -0400"),
        ("Message-ID", "<apt-20260707-1030@harborviewdental.com>"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ],
        "Hi,\r\n\r\n"
        "This confirms your cleaning appointment at Harborview Dental on\r\n"
        "Tuesday, July 7 at 10:30 AM with Dr. Okafor.\r\n\r\n"
        "Need to reschedule? Call us at (555) 014-2200 or reply to this email.\r\n\r\n"
        "Harborview Dental, 210 Marina Way\r\n")
    # Bluehost-class: NO Authentication-Results anywhere; the only proof of
    # identity is the message's own DKIM signature, verifiable locally.
    return _dkim_sign(raw, "harborviewdental.com")


# Manifest: ground truth by construction. ORDER IS THE PRESENTATION ORDER for
# Matt's label-approval checkpoint. "dkim_domain" is set only for fixtures
# carrying a real signature made with the embedded test key.
SYNTHETICS = [
    dict(filename="01-lookalike-domain-paypal.eml", label="spam",
         builder=_f01, dkim_domain=None,
         description="Lookalike-domain PayPal phish (paypa1-secure.com, digit-1 "
                     "homoglyph), unauthenticated, credential link"),
    dict(filename="02-punycode-homograph.eml", label="spam",
         builder=_f02, dkim_domain=None,
         description="Punycode/IDN homograph domain phish (xn--pypal-4ve.com), "
                     "unauthenticated"),
    dict(filename="03-display-name-spoof-apple.eml", label="spam",
         builder=_f03, dkim_domain=None,
         description="Display-name spoof: 'Apple Support' from an unrelated "
                     ".net mailer"),
    dict(filename="04-own-domain-auth-spam-random.eml", label="spam",
         builder=_f04, dkim_domain="bkzvqrelay.com",
         description="Own-domain-AUTHENTICATED spam, random-string domain "
                     "(bkzmpq/qentrivo/guinez class): valid DKIM, brand-matched, "
                     "still spam"),
    dict(filename="05-own-domain-auth-spam-word.eml", label="spam",
         builder=_f05, dkim_domain="brightoffersdaily.com",
         description="Own-domain-AUTHENTICATED spam, plausible-word domain: "
                     "valid DKIM, brand-matched, work-from-home scheme"),
    dict(filename="06-dkim-signed-phish-misaligned.eml", label="spam",
         builder=_f06, dkim_domain="mailblastpro.net",
         description="DKIM-signed phish: signature VALID for mailblastpro.net "
                     "but From claims paypal.com (alignment fails)"),
    dict(filename="07-cousin-domain-spf.eml", label="spam",
         builder=_f07, dkim_domain=None,
         description="Cousin-domain phish (amazon-account-security.com) with a "
                     "REAL spf=pass for the cousin domain itself"),
    dict(filename="08-reply-to-mismatch.eml", label="spam",
         builder=_f08, dkim_domain=None,
         description="Reply-To mismatch: From netflix-billing.com, Reply-To a "
                     "personal Gmail; asks for card details by reply"),
    dict(filename="09-credential-harvest-link.eml", label="spam",
         builder=_f09, dkim_domain=None,
         description="Mailbox-quota credential harvest; HTML body, link domain "
                     "(account-verify-center.xyz) unrelated to sender"),
    dict(filename="10-bec-wire-transfer.eml", label="spam",
         builder=_f10, dkim_domain=None,
         description="BEC wire-transfer lure: owner's own display name, plain "
                     "text, no links, pure urgency"),
    dict(filename="11-provider-flagged-pills.eml", label="spam",
         builder=_f11, dkim_domain=None,
         description="Provider-flagged pharmacy spam (X-Spam-Status: Yes) — "
                     "exercises the source=provider split"),
    dict(filename="12-gift-card-prize.eml", label="spam",
         builder=_f12, dkim_domain=None,
         description="Gift-card prize scam, unauthenticated, pay-shipping hook"),
    dict(filename="13-unsubscribe-bait-invisible.eml", label="spam",
         builder=_f13, dkim_domain=None,
         description="Clickbait junk with invisible padded preview text "
                     "(&zwnj; run) and tracking link"),
    dict(filename="14-legit-transactional-receipt.eml", label="legit",
         builder=_f14, dkim_domain=None,
         description="LEGIT transactional receipt: provider-stamped dkim=pass + "
                     "dmarc=pass, brand-matched (untested authenticated-legit "
                     "path)"),
    dict(filename="15-legit-authenticated-newsletter.eml", label="legit",
         builder=_f15, dkim_domain=None,
         description="LEGIT authenticated marketing newsletter (the Nordstrom "
                     "class: disliked but legitimate), dkim+dmarc pass, "
                     "brand-matched"),
    dict(filename="16-legit-bluehost-local-dkim.eml", label="legit",
         builder=_f16, dkim_domain="harborviewdental.com",
         description="LEGIT Bluehost-class small business: NO Authentication-"
                     "Results, own valid DKIM signature verifiable locally"),
]


def write_synthetics(out_dir) -> list:
    """Write all 16 fixtures into out_dir. Returns [(filename, n_bytes), ...]."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for spec in SYNTHETICS:
        data = spec["builder"]()
        (out / spec["filename"]).write_bytes(data)
        written.append((spec["filename"], len(data)))
    return written


def main():
    ap = argparse.ArgumentParser(
        description="Generate the 16 synthetic eval .eml fixtures.")
    ap.add_argument(
        "--out", default=str(DEFAULT_OUT),
        help=f"output directory (default: {DEFAULT_OUT})")
    args = ap.parse_args()

    written = write_synthetics(args.out)
    print(f"Wrote {len(written)} synthetic fixtures to {args.out}:")
    for name, size in written:
        print(f"  {size:6,}  {name}")
    print("\nNOTE: these enter the benchmark corpus only after the label list "
          "is approved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

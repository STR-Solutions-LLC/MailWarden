# (c) 2026 STR Solutions, LLC. All rights reserved.
from __future__ import annotations
"""
Live validators for the Anthropic API key, IMAP, and SMTP.

Implements §Appendix A1/A2/A3. These are called from Setup Assistant and
Dashboard → Settings. Runs on worker threads; UI code wraps them so the
window stays responsive.
"""
import imaplib
import re
import smtplib
from typing import Any


def validate_api_key(api_key: str) -> tuple[bool, str]:
    """§A1. Return (valid, user_facing_message)."""
    if not api_key.startswith("sk-ant-"):
        return False, "API key should begin with sk-ant-. Double-check what you pasted."
    try:
        import anthropic
    except ImportError:
        return False, "Anthropic SDK not installed. Reinstall MailWarden."

    # 15-second timeout so a stuck connection surfaces as an error rather
    # than hanging the UI forever.
    client = anthropic.Anthropic(api_key=api_key, timeout=15.0)
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=10,
            messages=[{"role": "user", "content": "Reply with OK."}],
        )
        if resp.content and getattr(resp.content[0], "text", "").strip():
            return True, "API key is valid."
        return False, "API responded unexpectedly. Try again."
    except anthropic.AuthenticationError:
        return False, "API key was rejected. Check that you copied the whole key."
    except anthropic.RateLimitError:
        return False, "Rate limited — wait a moment and try again."
    except anthropic.APITimeoutError:
        return False, ("Request timed out after 15 seconds. Check your internet "
                       "connection, or try again — sometimes Anthropic is slow.")
    except anthropic.APIConnectionError as e:
        return False, f"Could not reach api.anthropic.com: {e}"
    except Exception as e:
        return False, f"Network error: {type(e).__name__}: {e}"


def test_imap(host: str, port: int, username: str, password: str,
              timeout: float = 15.0) -> dict:
    """§A2. Return {'ok', 'error', 'folders', 'separator'}.
    The timeout guarantees we never hang — AOL in particular has accepted
    TCP but then never completed the SSL handshake, leaving the UI stuck."""
    if not host.strip():
        return {"ok": False, "error": "IMAP host is empty. Pick a provider preset "
                "or fill it in manually.",
                "folders": [], "separator": "."}
    try:
        conn = imaplib.IMAP4_SSL(host, port, timeout=timeout)
    except TimeoutError:
        return {"ok": False,
                "error": f"Timed out connecting to {host}:{port}. "
                         "Check that the host is correct and your internet is up.",
                "folders": [], "separator": "."}
    except OSError as e:
        return {"ok": False,
                "error": f"Could not connect to {host}:{port} — {e}. "
                         "Check the host name and port.",
                "folders": [], "separator": "."}
    except Exception as e:
        return {"ok": False,
                "error": f"Could not connect to {host}:{port} — {type(e).__name__}: {e}",
                "folders": [], "separator": "."}

    try:
        try:
            conn.login(username, password)
        except imaplib.IMAP4.error as e:
            msg = str(e).lower()
            if "authentication" in msg or "invalid credentials" in msg:
                return {"ok": False, "error":
                        "Authentication failed. For Gmail and AOL, you must use an "
                        "App Password, not your regular password.",
                        "folders": [], "separator": "."}
            return {"ok": False, "error": f"IMAP error: {e}",
                    "folders": [], "separator": "."}

        # conn.list() can raise imaplib.IMAP4.error, OSError, or ssl errors
        # depending on the provider (AOL has been the worst offender — it
        # accepts the login, then the handshake for LIST hangs or returns
        # malformed bytes). An unhandled exception here was what made
        # AOL failures invisible to the user in the Setup Assistant.
        try:
            status, folders = conn.list()
        except imaplib.IMAP4.error as e:
            return {"ok": False,
                    "error": f"The server refused the folder listing: {e}. "
                             "This is the symptom AOL produces when the "
                             "App Password flow was not completed.",
                    "folders": [], "separator": "."}
        except Exception as e:
            return {"ok": False,
                    "error": f"Folder listing failed "
                             f"({type(e).__name__}: {e}).",
                    "folders": [], "separator": "."}

        if status != "OK":
            return {"ok": False,
                    "error": f"Server returned status {status!r} for LIST.",
                    "folders": [], "separator": "."}

        sep = "."
        names = []
        try:
            if folders:
                m = re.match(r'\(.*?\)\s+"([^"]+)"\s+', folders[0].decode())
                if m:
                    sep = m.group(1)
            for f in folders or []:
                fm = re.match(r'\(.*?\)\s+"[^"]+"\s+(.+)', f.decode())
                if fm:
                    name = fm.group(1).strip()
                    if name.startswith('"') and name.endswith('"'):
                        name = name[1:-1]
                    names.append(name)
        except Exception as e:
            return {"ok": False,
                    "error": f"Could not parse folder list "
                             f"({type(e).__name__}: {e}).",
                    "folders": [], "separator": "."}

        if not names:
            # Reaching here means LIST said OK and we got zero folders —
            # no real account has zero folders, so treat as a failure
            # rather than showing an empty junk-folder dropdown.
            return {"ok": False,
                    "error": "The server returned zero folders. "
                             "The account may require an App Password, "
                             "or the IMAP prefix may need adjusting.",
                    "folders": [], "separator": "."}

        return {"ok": True, "error": "", "folders": sorted(names), "separator": sep}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def safe_smtp_connect(host: str, port: int, username: str, password: str,
                      use_starttls: bool = True, timeout: int = 15):
    """Return a logged-in SMTP server. Refuses plaintext credential submission.

    port == 465                     → smtplib.SMTP_SSL (implicit TLS)
    port != 465 and use_starttls    → smtplib.SMTP + STARTTLS
    port != 465 and not use_starttls → RuntimeError

    The third branch protects users who misconfigure: smtplib.SMTP.login()
    happily transmits the username and password in the clear over an
    unencrypted socket, and we do not want to do that silently.
    """
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=timeout)
        server.ehlo()
    else:
        if not use_starttls:
            raise RuntimeError(
                f"Refusing to submit SMTP credentials to {host}:{port} "
                f"without TLS. Enable STARTTLS or switch to port 465."
            )
        server = smtplib.SMTP(host, port, timeout=timeout)
        server.ehlo()
        server.starttls()
        server.ehlo()
    server.login(username, password)
    return server


def test_smtp(host: str, port: int, username: str, password: str,
              use_starttls: bool = True) -> tuple[bool, str]:
    """§A3. Return (ok, message)."""
    server = None
    try:
        server = safe_smtp_connect(host, port, username, password, use_starttls)
        return True, "SMTP authentication successful."
    except smtplib.SMTPAuthenticationError:
        return False, ("SMTP rejected the login. For Gmail and AOL you must "
                       "use an App Password.")
    except RuntimeError as e:
        return False, str(e)
    except Exception as e:
        return False, f"SMTP error: {e}"
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


def check_billing(api_key: str) -> dict:
    """§A4. Return {'available', 'balance_usd', 'message'}."""
    import urllib.request
    import urllib.error
    import json

    url = "https://api.anthropic.com/v1/organizations/billing/credit_grants"
    req = urllib.request.Request(url, headers={
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            bal = data.get("balance") or data.get("remaining_balance_usd")
            if bal is not None:
                return {"available": True, "balance_usd": float(bal),
                        "message": f"Remaining credit: ${float(bal):.2f}"}
            return {"available": False, "balance_usd": None,
                    "message": "Balance endpoint returned unexpected data. "
                               "Check directly at console.anthropic.com/settings/billing"}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"available": False, "balance_usd": None,
                    "message": "Live balance not available on personal plans. "
                               "Check at console.anthropic.com/settings/billing"}
        return {"available": False, "balance_usd": None,
                "message": f"Billing check returned {e.code}. "
                           "Check at console.anthropic.com/settings/billing"}
    except Exception:
        return {"available": False, "balance_usd": None,
                "message": "Could not reach billing API. "
                           "Check at console.anthropic.com/settings/billing"}


def send_test_email(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
                    from_addr: str, to_addr: str) -> tuple[bool, str]:
    """Send a plain-text test email so the user can confirm SMTP works end-to-end."""
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = "MailWarden test message"
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(
        "This is a test message from MailWarden Setup Assistant.\n\n"
        "If you received this, your SMTP settings are working correctly.\n"
        "You can now close this email and continue setup.\n"
    )
    server = None
    try:
        server = safe_smtp_connect(smtp_host, smtp_port, smtp_user, smtp_pass)
        server.send_message(msg)
        return True, f"Test email sent to {to_addr}."
    except Exception as e:
        return False, f"Could not send test email: {e}"
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


# Provider presets — mirrors Apple Mail's built-in list so users recognize
# the options. Picking a preset pre-fills host + port + guidance text for
# App Password requirements. "Other" leaves everything blank for custom
# hosts like Bluehost, Fastmail, self-hosted Dovecot, etc.
PROVIDER_PRESETS: list[dict[str, Any]] = [
    {"label": "iCloud",
     "imap_host": "imap.mail.me.com", "imap_port": 993,
     "smtp_host": "smtp.mail.me.com", "smtp_port": 587,
     "needs_app_password": True,
     "note": "iCloud requires an App-Specific Password. "
             "Generate at https://account.apple.com → Sign-In and Security → App-Specific Passwords."},
    {"label": "Gmail",
     "imap_host": "imap.gmail.com", "imap_port": 993,
     "smtp_host": "smtp.gmail.com", "smtp_port": 587,
     "needs_app_password": True,
     "note": "Gmail requires an App Password. "
             "Generate at https://myaccount.google.com/apppasswords (2-Step Verification must be on)."},
    {"label": "Outlook / Office 365",
     "imap_host": "outlook.office365.com", "imap_port": 993,
     "smtp_host": "smtp.office365.com", "smtp_port": 587,
     "needs_app_password": True,
     "note": "Outlook / Office 365 requires an App Password when 2FA is on. "
             "Generate in account.microsoft.com → Security → App passwords."},
    {"label": "Yahoo",
     "imap_host": "imap.mail.yahoo.com", "imap_port": 993,
     "smtp_host": "smtp.mail.yahoo.com", "smtp_port": 587,
     "needs_app_password": True,
     "note": "Yahoo requires an App Password. "
             "Generate at https://login.yahoo.com/account/security → Generate app password."},
    {"label": "AOL",
     "imap_host": "imap.aol.com", "imap_port": 993,
     "smtp_host": "smtp.aol.com", "smtp_port": 587,
     "needs_app_password": True,
     "note": "AOL requires an App Password. "
             "Generate at https://login.aol.com/account/security → Generate app password."},
    {"label": "Other",
     "imap_host": "", "imap_port": 993,
     "smtp_host": "", "smtp_port": 587,
     "needs_app_password": False,
     "note": "For other providers (Bluehost, Fastmail, self-hosted, etc.) "
             "check your provider's help page for IMAP and SMTP server names."},
]

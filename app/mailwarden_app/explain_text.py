# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Plain-English explanation library for the "Check an Email" screen (Phase 1a).

When MailWarden blocks an email BEFORE the AI runs (header checks or your
allow/block lists), there is no model-written "why" — so this module turns the
internal signal names + list matches into the plain-English wording the owner
approved. Once an email reaches the AI, the model's own ``reasoning`` is used
verbatim.

Pure module: standard library only, NO tkinter and NO engine import, so it is
fully unit-testable headless. The dashboard screen composes these helpers.
"""
import email
import re

# Pre-filter signals that BLOCK on their own (no AI, $0). Everything else is a
# "soft" signal that is merely noticed and routed to Claude for the real call.
_HARD_SIGNALS = {
    "SPF_DKIM_BOTH_FAIL",
    "LEAKED_AI_PROMPT",
    "PROMPT_INJECTION_HARD",
    "IP_DNSBL_MULTIPLE",
}

# Static plain-English sentences, keyed by signal name. The two domain-mismatch
# signals and the prompt-injection pair are handled specially below.
_SIGNAL_TEXT = {
    # --- hard (instant block) ---
    "SPF_DKIM_BOTH_FAIL":
        "This email failed both of the automatic checks that confirm a message "
        "really came from the address it claims. Failing both is a strong sign "
        "the sender's address was forged.",
    "LEAKED_AI_PROMPT":
        "This email still contained the setup instructions from the AI tool that "
        "mass-produced it — text that only shows up in machine-generated spam, "
        "never in a real message.",
    "PROMPT_INJECTION_HARD":
        "This email contained hidden commands trying to trick MailWarden's AI "
        "into ignoring its rules and marking the message 'safe' — something no "
        "legitimate sender does.",
    "IP_DNSBL_MULTIPLE":
        "The computer that sent this email is on several public lists of known "
        "spam-sending machines.",
    # --- soft (noticed, not enough alone -> sent to Claude) ---
    "SPF_OR_DKIM_FAIL":
        "One of the two checks that confirm a sender's identity failed. That can "
        "happen with forwarded or mailing-list mail, so on its own it's a yellow "
        "flag, not proof.",
    "ELEVATED_SPAM_SCORE":
        "The sender's own mail provider had already marked this message as likely "
        "spam.",
    "LIST_UNSUB_TRANSACT":
        "This is a bulk mailing (it has an unsubscribe link) dressed up as a "
        "personal notice like a delivery, invoice, or prize — a pattern scammers "
        "favor.",
    "DEGRADED_PLAIN_TEXT":
        "The email had almost no readable text — it was empty, extremely short, "
        "or made of code/gibberish instead of normal writing, a trick spam uses "
        "to slip past filters.",
    "IP_DNSBL_SINGLE":
        "The computer that sent this email appears on one public list of "
        "suspected spam machines.",
    # Prompt-injection soft pair: ATTEMPT carries the sentence; BOOST is the
    # internal counting twin and produces no separate line (collapsed).
    "PROMPT_INJECTION_ATTEMPT":
        "The email contained phrasing that looks like an attempt to manipulate an "
        "AI assistant. On its own it won't block the message, but it counts as a "
        "warning sign.",
    "PROMPT_INJECTION_ATTEMPT_BOOST": "",
}

_TWO_DOMAIN_RE = re.compile(
    r"domain '([^']+)' differs from From domain '([^']+)'", re.IGNORECASE)


def pre_signal_is_hard(name: str) -> bool:
    """True if this pre-filter signal blocks on its own (no AI call)."""
    return name in _HARD_SIGNALS


def explain_pre_signal(name: str, detail: str = "") -> str:
    """Return the plain-English sentence for one pre-filter signal name.

    ``detail`` is the engine's signal_details string; for the two domain-
    mismatch signals the real domains are pulled out of it and filled in.
    Unknown signals get a safe generic sentence (never crashes).
    """
    if name == "REPLY_TO_MISMATCH":
        m = _TWO_DOMAIN_RE.search(detail or "")
        if m:
            return (f"If you replied, your answer would go to a different domain "
                    f"({m.group(1)}) than the address it appears to come from "
                    f"({m.group(2)}) — a common scam setup, though some mailing "
                    f"lists do it too.")
        return ("If you replied, your answer would go to a different domain than "
                "the address this email appears to come from — a common scam "
                "setup, though some mailing lists do it too.")
    if name == "MESSAGE_ID_MISMATCH":
        m = _TWO_DOMAIN_RE.search(detail or "")
        if m:
            return (f"The hidden tracking ID on this email comes from a different "
                    f"domain ({m.group(1)}) than the sender's ({m.group(2)}), "
                    f"which can mean the 'from' address was faked (but is normal "
                    f"for some senders).")
        return ("The hidden tracking ID on this email comes from a different "
                "domain than the sender's, which can mean the 'from' address was "
                "faked (but is normal for some senders).")
    if name in _SIGNAL_TEXT:
        return _SIGNAL_TEXT[name]
    # Unknown / future signal — stay graceful and honest.
    return ("MailWarden flagged a technical warning sign on this email "
            f"({name.replace('_', ' ').lower()}).")


def explain_pre_signals(hard_signals, soft_signals, signal_details) -> dict:
    """Turn the engine's hard/soft signal lists into two lists of sentences.

    Returns {"blocked": [...], "noticed": [...]}. The prompt-injection pair and
    any duplicate sentences are collapsed to a single line.
    """
    signal_details = signal_details or {}

    def _render(names):
        out, seen = [], set()
        for n in names:
            s = explain_pre_signal(n, signal_details.get(n, ""))
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    return {
        "blocked": _render(hard_signals or []),
        "noticed": _render(soft_signals or []),
    }


def explain_list_match(list_match: dict) -> str:
    """Plain-English reason for a deterministic allow/block-list decision."""
    kind = (list_match or {}).get("kind", "")
    value = (list_match or {}).get("value", "")
    if kind == "whitelist_address":
        return (f"You've added this sender to your allow-list ({value}), so "
                f"MailWarden always lets it through without running the spam check.")
    if kind == "whitelist_domain":
        return (f"You've allow-listed this sender's domain ({value}), so "
                f"MailWarden always lets it through without running the spam check.")
    if kind == "blacklist_address":
        return f"You've blocked this exact sender ({value})."
    if kind == "blacklist_domain":
        return f"You've blocked everything from this domain ({value})."
    if kind == "blacklist_display_name":
        return f"You've blocked the sender name '{value}'."
    if kind == "subject_keyword":
        return (f"The subject line contains a word you told MailWarden to always "
                f"block ('{value}').")
    return "Matched one of your allow/block-list rules."


def explain_ai_outcome(ai: dict, final_decision: str, threshold: float = 0.85) -> dict:
    """Return {"headline", "why"} for the AI stage.

    ``why`` is Claude's own plain-language reasoning (verbatim). Handles the
    no-key / failed cases gracefully.
    """
    if not ai or "error" in ai:
        err = (ai or {}).get("error", "")
        if err == "no_api_key":
            return {"headline": "Claude didn't review this — add your Claude API "
                                "key in Settings first, then check again.",
                    "why": ""}
        return {"headline": "Claude couldn't finish the review this time (a "
                            "connection or service error). Try again in a moment.",
                "why": ""}

    decision = ai.get("decision", "NOT_SPAM")
    conf = ai.get("confidence", 0.0) or 0.0
    why = ai.get("reasoning", "") or ""
    pct = int(round(conf * 100))
    thr = int(round(threshold * 100))

    if decision == "SPAM" and final_decision == "JUNK":
        headline = f"Claude reviewed it and is confident this is junk ({pct}%)."
    elif decision == "SPAM":
        headline = (f"Claude leaned toward junk but wasn't sure enough to block "
                    f"it ({pct}%, below the {thr}% line), so MailWarden let it "
                    f"through.")
    else:
        headline = "Claude reviewed it and judged it a normal message."
    return {"headline": headline, "why": why}


def looks_like_email(data) -> bool:
    """True if ``data`` parses as an email with at least one real header.

    Guards the paste field: a body-only / random-text paste returns False so the
    screen can show the friendly "paste the full raw source" message.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    try:
        msg = email.message_from_bytes(data)
    except Exception:
        return False
    keys = {k.lower() for k in msg.keys()}
    return bool(keys & {"from", "to", "subject", "date", "received",
                        "message-id", "return-path", "cc", "reply-to"})


# Comprehensive "how do I get the raw source?" help, shown on the (?) rollover
# next to the paste field. Mail apps change their menus over time.
RAW_SOURCE_HELP = (
    "How to get an email's raw source:\n\n"
    "• Gmail (web): open the email → ⋮ (top-right) → Show original → Copy to clipboard.\n"
    "• Apple Mail (Mac): open the email → View → Message → Raw Source (or press ⌥⌘U).\n"
    "• Apple Mail (iPhone/iPad): can't show raw source — open the same email in webmail, "
    "or forward it to a computer.\n"
    "• Outlook on the web: open the email → ⋯ (More actions) → View → View message source.\n"
    "• Outlook (Windows desktop): double-click the email → File → Properties → copy the "
    "Internet headers box. (Headers only; for the full message use Outlook on the web.)\n"
    "• Yahoo Mail (web): open the email → ⋯ (More) → View raw message.\n"
    "• AOL Mail (web): open the email → ⋯ / More → View Message Source.\n"
    "• Thunderbird: select the email → View → Message Source (or ⌘U / Ctrl+U).\n"
    "• Proton Mail (web): open the email → ⋯ (More) → View headers (or Export for the full source).\n"
    "• Any other app: look for 'Show original', 'View source', or 'View raw message' in the "
    "message's More/⋯ or View menu.\n\n"
    "Copy everything — the block of technical lines at the top AND the message below — "
    "and paste it here."
)

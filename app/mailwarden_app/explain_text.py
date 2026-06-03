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

# Pre-filter signals that BLOCK on their own (no AI, $0). These are the ONLY
# pre-filter signals; any other message is routed to Claude for the real call.
_HARD_SIGNALS = {
    "SPF_DKIM_BOTH_FAIL",
    "LEAKED_AI_PROMPT",
    "PROMPT_INJECTION_HARD",
    "IP_DNSBL_MULTIPLE",
}

# Static plain-English sentences, keyed by signal name. All pre-filter signals
# are HARD (instant block) now — soft signals were removed. Non-hard, non-listed
# mail is routed to Claude, whose own reasoning is shown verbatim.
_SIGNAL_TEXT = {
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
}


def pre_signal_is_hard(name: str) -> bool:
    """True if this pre-filter signal blocks on its own (no AI call)."""
    return name in _HARD_SIGNALS


def explain_pre_signal(name: str, detail: str = "") -> str:
    """Return the plain-English sentence for one pre-filter signal name.

    ``detail`` is the engine's signal_details string (currently unused — all
    remaining signals have static wording). Unknown signals get a safe generic
    sentence (never crashes).
    """
    if name in _SIGNAL_TEXT:
        return _SIGNAL_TEXT[name]
    # Unknown / future signal — stay graceful and honest.
    return ("MailWarden flagged a technical warning sign on this email "
            f"({name.replace('_', ' ').lower()}).")


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

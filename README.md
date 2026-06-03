# MailWarden

AI-powered anti-phishing & spam filter for macOS. Claude reads every incoming email the way a careful person would — catching the lookalike-domain, fake-urgency phishing that slips past generic filters — and learns *your* spam over time.

## Why it exists
Phishing has gotten good enough that even careful people get fooled, and the people most at risk are often the ones least able to tell a real email from a fake — older parents, relatives, anyone who can't easily spot a lookalike domain or a bogus "your account is suspended" notice. MailWarden puts a careful reader in front of their inbox, so the dangerous stuff is gone before they ever see it.

## What it does, and how
MailWarden connects to your email accounts (using your own Anthropic API key) and has Claude read each incoming message — understanding context, not just matching keywords. It does two jobs:

- **Protect — catch the threats.** Claude reads each message in context to catch the phishing, scams, and impersonation a vulnerable person misses — the lookalike domain, the fake "your account is suspended," the urgent ask from someone pretending to be your bank.
- **Curate — remove mail you don't want.** Quietly remove legitimate mail you simply don't want anymore — political fundraising, a company that won't stop. This isn't calling it spam. It's your preference, applied precisely. Block a specific sender outright, or teach a pattern Claude removes wherever it appears.
- **Teach it by example.** Forward a spam example with a sentence about *why*, or use the built-in "Check an Email" screen to see exactly why any message would be blocked or let through — and teach it right there. It turns your example into a *general* rule (or tells you honestly when it can't), and every rule waits for your one-click approval before it does anything.

After a few weeks you don't have a generic filter — you have one that knows *your* spammers.

## Heads-up: not built for non-technical users
This is a beta, and setup assumes some comfort with technical steps — most importantly, creating and funding your own Anthropic API key. There's thorough in-app Help once you're running, but if you've never touched an API key, expect a learning curve (or a hand from someone who has).

## Cost
You pay Anthropic directly for what Claude reads. As a rough guide, about **$0.50 to cover four busy accounts over 24 hours**. Cost depends on how many accounts you run and how much mail you get — **not** on how often MailWarden checks. You can cap your spend in the Anthropic console.

## Platform support
- ✅ **Apple Silicon (M1–M4+)** — fully tested.
- ⚠️ **Intel Macs** — not supported yet, but subject to further refinement. We'd genuinely welcome your feedback: if you try it and it fails, copy the diagnostic windows and send them to **info@rentalist.pro**.
- ❌ **Windows** — not supported.
- Requires macOS Sonoma (14.x) or later.

## Install (beta)
1. Download the latest `.pkg` from [Releases](https://github.com/STR-Solutions-LLC/MailWarden/releases).
2. Double-click to install — it's signed by STR Solutions, LLC and notarized by Apple, so Gatekeeper accepts it without warnings.
3. Step through the installer, then open `/Applications/MailWarden.app`. A Setup Assistant walks you through your first account and API key.
4. When macOS asks, approve MailWarden in **System Settings → General → Login Items & Extensions → Allow in the Background** — without this, the background filter and menu-bar agent won't start.

MailWarden then runs in the background on its own. **It lives in the menu bar — there's no Dock icon.** Open the dashboard anytime from the menu-bar icon, and you'll get a short report email each morning.

## You'll need
- An Apple Silicon Mac on macOS Sonoma or later
- Your own Anthropic API key (https://console.anthropic.com) — funded on the workspace that owns the key
- An email account with IMAP + SMTP access (Gmail and AOL need an app password — the Setup Assistant links you to the right page)

## Privacy
MailWarden runs entirely on your Mac. It talks to your email server, the Anthropic API, and (about every two weeks) GitHub to check for updates. That's the whole list — no telemetry, no analytics, no phoning home. Your email content never leaves the classification pipeline.

## Feedback
Email **info@rentalist.pro**. We may reply to ask for details that help us improve — but note that **no customer support is offered** for this beta.
GitHub Issues: https://github.com/STR-Solutions-LLC/MailWarden/issues

## Credits
Published by STR Solutions, LLC. Conceived and architected by Matt Rosenberg ([linkedin.com/in/mattrosenberg](https://www.linkedin.com/in/mattrosenberg)), written with the help of Claude Code (Opus 4.8). *MailWarden is an independent product and is not affiliated with, endorsed by, or sponsored by Anthropic.*

## License
PolyForm Noncommercial License 1.0.0 — free for personal, educational, research, and other non-commercial use. Commercial licensing available: info@rentalist.pro. Full text: [LICENSE](LICENSE).

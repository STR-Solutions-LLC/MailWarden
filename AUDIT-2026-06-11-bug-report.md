# MailWarden Comprehensive Audit — June 11, 2026

**Version audited:** v1.6.0-beta.16.2 (branch `calibration-security-build1`, clean)
**Method:** 8 specialized read-only audit agents covered the IMAP runtime, the teach/approve loop, header heuristics, the signal learner, the daily report, the GUI/config layer, security, and spam-detection quality. Every finding was verified against the actual code paths; several were reproduced by executing the real functions against test inputs. **No code was changed. Nothing was fixed. This is an audit only.**

**The headline:** The app genuinely runs well day-to-day — the per-account error isolation, atomic file writes, plain-text-only outgoing email, TLS verification, prompt-injection delimiters, and the approval-before-apply rule are all solid. But underneath, there are about 56 latent issues you can't see from behavior. Three themes dominate:

1. **Five programs share the same files with no traffic cop.** The filter, the detached learner, the daily report, the menu-bar agent, and the Dashboard all read-modify-write the same JSON files. Writes are atomic (the files never corrupt), but changes silently overwrite each other — including a rule you explicitly approved.
2. **The email-command interface trusts a forgeable "From" line.** Anyone who can land an email in your inbox with your address typed in the From field can whitelist themselves or approve a pending rule. The code that could verify authenticity already exists in the app — it's just never called on this path.
3. **The teaching loop can silently learn the wrong thing.** Certain forward formats make the filter learn from the wrong sender — including your own address — and the database poisoning is invisible.

---

## How to read severity

- **CRITICAL** — silent data loss/corruption, a security bypass, or a core control that doesn't actually work.
- **HIGH** — wrong behavior on a common path, or a failure that happens silently.
- **MEDIUM** — edge cases, wasted cost, or slow degradation over months.
- **LOW** — robustness and polish.

Items marked **[MATT DECIDES]** involve product behavior — per your rules, nothing in those areas gets changed without a plain-English discussion with you first.

---

# PART 1 — BUGS BY SEVERITY

## CRITICAL (10)

### C1. Email commands and rule approvals trust a forgeable From line
**What it means:** You control MailWarden by email — "Whitelist", "Blacklist All", "NOT SPAM", replying "YES" to a proposal. The only check that a command really came from you is whether the From line *says* your address. A From line is just text anyone can type. A malicious sender who lands one forged email in your inbox can whitelist their own domain, blacklist a sender you rely on, or approve a pending rule — with zero interaction from you. Making it worse, approval IDs (SFIDs) are predictable (date + 3-digit counter), so an attacker doesn't even need to have seen the proposal email. The app already contains a correct SPF/DKIM/DMARC verifier (`utils.summarize_authentication`) — it is simply never consulted on the command path.
**Where:** `payload/MailWarden/src/spam_filter.py:1503` (`_command_sender_is_owner`), used at `:3327` and `:4207`.
**[MATT DECIDES]:** the fix policy — what happens when a *real* command from you fails authentication (some legitimate forwards do). Reject silently, reject with a notice email, or warn-but-honor?
*(Audit refs: T3, S1, S2)*

### C2. Teaching by forwarding can learn the wrong sender — including blacklisting yourself
**What it means:** Two reproduced failure modes. (a) A spam email that *contains* a fake "Begin forwarded message: From: admin@yourbank.com" block inside its own body tricks the parser — forward it with "Blacklist All" and MailWarden blacklists *yourbank.com* (the address the spammer chose), not the spammer. (b) If you forward spam *inline* and your mail client inserts an "On Mon… Matt <you@…> wrote:" line, the parser extracts **your own address** as the spam sender — "Blacklist All" then blacklists *you*, and "SPAM Example" teaches the filter your own identity is a spam source. Both poison the database invisibly; you just get a normal "Confirmed" reply.
**Where:** `spam_filter.py:1066` and `:1157` (`parse_forwarded_email`); consumed by every command handler.
*(Audit refs: T1, T2 — both reproduced)*

### C3. "Dry Run" isn't actually dry **[MATT DECIDES]**
**What it means:** Dry run only suppresses the final spam *move*. Everything else still happens for real: messages in the Train folder are **permanently deleted**, command emails are marked read, whitelist/blacklist/signal files are modified, confirmation emails are sent, and the learner spawns. Someone using dry run to safely evaluate the app is having irreversible things happen. Related: the daily report counts dry-run detections under "Spam moved to Junk" even though nothing moved.
**Where:** `spam_filter.py:3176-3178` (the only dry-run guards), `:2801-2802` (Train-folder expunge runs regardless).
**[MATT DECIDES]:** what "dry run" should promise the user — that's a product definition.
*(Audit refs: R1, D14)*

### C4. The confidence-threshold slider in Settings does nothing
**What it means:** The Dashboard saves the slider under `anthropic.confidence_threshold`; the filter engine reads `filter.confidence_threshold`, which never exists, so the engine uses the hard-coded 0.85 forever. Any user who adjusts this control gets "Saved." and zero effect. Different parts of the app even disagree internally about which key is live.
**Where:** write `app/mailwarden_app/dashboard.py:3313`; read `payload/MailWarden/src/spam_filter.py:3180`.
*(Audit ref: G1 — fully verified)*

### C5. Domains whose DKIM check FAILED are presented to the AI as "cryptographically PROVEN"
**What it means:** When an email carries multiple DKIM results (common), one passing result anywhere makes the code harvest *every* domain mentioned — including domains on the *failing* lines. Reproduced: `dkim=fail header.d=evil.ru; dkim=pass header.d=good.com` → both `evil.ru` and `good.com` reported as proven senders. An attacker can deliberately attach a passing signature for a throwaway domain alongside a failing forged-brand signature, and the forged brand gets presented to the classifier as verified. SPF/DMARC parsing has a related "first token wins" flaw, and only the first Authentication-Results header is read with no check of who wrote it.
**Where:** `payload/MailWarden/src/utils.py:219-223`; header selection `spam_filter.py:2266`.
*(Audit refs: H2, H7)*

### C6. Legitimate AI/marketing email can be silently hard-junked by the prompt-injection detectors **[MATT DECIDES in part]**
**What it means:** This one is aimed directly at your business. The detectors that auto-junk without any AI review fire on ordinary content: a newsletter quoting a chat transcript ("Human: … / Assistant: …"), marketing copy like "Forget everything you know about old SEO…", and an email-marketing SaaS describing "Detected campaign type:" and "Creative style mode:" features. All reproduced — each is deterministically junked for $0 with no model reasoning and no trace you'd notice. For someone in marketing who receives email *about* AI tools, this is a live false-positive risk.
**Where:** `utils.py:444-457` and `:511-554`; consumed at `spam_filter.py:584-590`.
**[MATT DECIDES]:** the marker lists and whether these stay hard auto-junk signals or get downgraded to "send to the AI for judgment."
*(Audit refs: H3, H4 — reproduced)*

### C7. No coordination between the five programs sharing files — silent lost updates everywhere
**What it means:** One root cause, many symptoms. Atomic writes keep files *valid*, but two programs that each load → modify → save will silently erase each other's changes. Confirmed instances:
- A refinement you **explicitly approved** can vanish minutes later when the learner blind-saves its older snapshot of `signals.json` — the confirmation email already said "applied." *(L1)*
- The learner rewrites the entire `config.json` to update one timestamp — a settings change, a re-added account, or a new API key saved in the Dashboard during a learner run gets silently reverted. *(L3)*
- The "filter lock" is an mtime check with a 10-minute staleness window, not a real lock: it has a check-then-write race, never verifies the holding process is alive, and any run longer than 10 minutes (slow API, big inbox) gets a second run started *concurrently*, double-billing and clobbering `processed_ids.json`. *(R3)*
- Learner token spend is routinely erased by the filter's end-of-run save — your cost numbers are systematically understated. *(R4, L5, D2)*
- The daily report is a *third* writer of the cost ledger, and Dashboard list edits race the filter's command handlers — a whitelist/blacklist entry you add can silently disappear. *(D3, R5, G3)*
- A learner-created proposal can be erased before its email is ever sent. *(T5)*
- Concurrent appends to `decisions.log` can interleave, merging two records and miscounting the report. *(D5)*
**Fix shape:** one shared file-lock helper used by all writers (the learner already uses a proper `flock` for itself — the pattern exists in the codebase).
*(Audit refs: R3, R4, R5, G3, L1, L3, L5, D2, D3, D5, T5 — all confirmed)*

### C8. The learner's AI prompt can be escaped via Received headers (rule poisoning)
**What it means:** The learner wraps untrusted email content in `<untrusted_email>` tags and sanitizes From/Subject/body so an attacker can't break out — but **Received headers were missed**. They're attacker-influenceable and are pasted into the prompt unsanitized, so a crafted header can close the untrusted block and inject instructions (e.g., propose "trust bank-phish.com"). The Train-folder path means the entire email, headers included, is attacker-controlled — the user just drags a message into a folder. Human approval is the last line of defense; the structural defense has a hole.
**Where:** `learn_signals.py:338-341` and `:507-510`.
*(Audit ref: L2)*

### C9. The blacklist folder sync breaks on the new scoped-entry format **[MATT DECIDES in part]**
**What it means:** The filter supports per-account scoped block entries (`{"value": …, "scope": [...]}`). The daily report's IMAP folder sync only knows the old plain-string format: it can only ever create *global* blocks, and worse — if the file already contains even one scoped entry, the sync **crashes** (`.lower()` on a dict) and the user's dragged-in `.eml` is silently lost. Dashboard-created scoped entries and folder-drag sync currently cannot coexist.
**Where:** `daily_report.py:447-456, 538-547` vs `spam_filter.py:310-349`.
**[MATT DECIDES]:** should a folder-dragged block be global or scoped to the account it came from?
*(Audit ref: D4)*

### C10. The daily report can silently skip or double-count hours of activity **[MATT DECIDES]**
**What it means:** The report covers "24 hours back from whenever it runs" — but it runs at 8:00 *or whenever the Mac next wakes*. Consecutive windows almost never tile: a Mac asleep at 8:00 produces seams of time that appear in no report (or in two). The report is your heartbeat and your accounting — it under-counts invisibly, and the email still arrives looking normal. Twice-yearly DST shifts add a one-hour version of the same problem.
**Where:** `daily_report.py:615, 663, 838, 866`; schedule `com.mailwarden.report.plist`.
**[MATT DECIDES]:** report semantics — a true calendar day (8:00→8:00 with a persisted watermark, no gaps possible) vs. rolling 24h.
*(Audit refs: D1, D11)*

---

## HIGH (14)

### B1. HTML-only emails are classified almost blind
The classifier receives only the first 500 characters of the *plain-text* body, with **no HTML fallback** (the forward parser has one; the classifier doesn't). Verified: the McAfee phishing test fixture sends an **empty body** to the model. Much of real spam is HTML-only. The model also never sees any URLs (no link extraction exists anywhere), even though its own RULE 1 asks it to judge link domains. `spam_filter.py:2118-2119`. *(Quality 1-A)*

### B2. Re-running the Setup Assistant wipes settings back to defaults
Setup starts from `DEFAULT_CONFIG` and saves wholesale — it never merges the existing config. A user routed into Setup by a corrupted config (or who re-runs it) loses dry-run state, model choice, intervals, per-account spam actions, and EULA-sent tracking (causing duplicate EULA emails). `setup_assistant.py:49, 409-441`. *(G2)*

### B3. Approval IDs (SFIDs) can collide → the wrong rule gets approved
The sequence number is `count of today's conversations + 1`, not `max + 1` — reproduced: with only `-002` existing, the next ID generated is `-002` again. A "YES" then matches the *first* conversation with that ID. Both `spam_filter.generate_sfid` and `learn_signals.next_sfid` share the flaw. `spam_filter.py:893`, `learn_signals.py:157`. *(T4)*

### B4. Reply understanding misfires in both directions **[MATT DECIDES in part]**
Reproduced: "**no**ted, go ahead" → treated as NO (prefix match on "no"); "**Yes, but** only for newsletters" → treated as unconditional YES and applied immediately, ignoring your condition. The most common natural phrasings are wrong in both directions. `spam_filter.py:1530`. **[MATT DECIDES]:** should "yes, but…" auto-apply or open a follow-up question? *(T6, T7)*

### B5. Trailing-dot addresses evade both lists
`a@spammer.com.` (trailing dot — resolves identically in DNS) bypasses a blacklist entry for `spammer.com`, and `a@chase.com.` fails to match a whitelist for `chase.com`. Reproduced. `utils.py:99-119`. *(H5)*

### B6. Two different From-parsers disagree about who sent the email
The lists use one parser, the AI prompt and brand-matching use another. For `From: "Chase <svc@chase.com>" <x@evil.ru>` the lists check `x@evil.ru` while the AI is told the sender is `svc@chase.com`. A standing attribution hazard — the lists, prompt, and brand logic should see one canonical sender. `utils.py:95` vs `spam_filter.py:2179`. *(H1)*

### B7. All progress is saved only at the very end of a run
`processed_ids` and token accounting are written once after the full multi-account run. A sleep/crash/kill mid-run (launchd does SIGKILL the process group — documented in the code's own comments) loses the record of everything processed: already-acted IMAP changes are unrecoverable, every evaluated email gets re-billed next run, and cost accounting undercounts. `spam_filter.py:3186/3199 → 4815/4818`. *(R2)*

### B8. Teaching examples can be silently skipped forever
The learner's "what's new" check compares file times against a timestamp taken at the *end* of its run. An example saved while a learner is already running falls before that timestamp and is never analyzed — no proposal, no error. `learn_signals.py:1330-1339, 1434`. *(L4)*

### B9. `decisions.log` grows forever and the report reads all of it, three times, every day
No rotation or pruning anywhere; tens of MB per year for a busy multi-account user; the daily report does full-file reads and regex passes over total history to report one day. Eventually slow or failing — and a failing report is invisible (see B10). `daily_report.py:623-624, 670-671, 880-881`. *(D6)*

### B10. If the daily report can't send, nothing tells you
SMTP failure is logged to a file you'll never open and the day's report is simply gone — no retry, no fallback notification, no menu-bar indicator. The report is the alerting channel, so its own death is undetectable. A `last_successful_report` watermark surfaced in the menu bar would fix the visibility. `daily_report.py:1207-1209, 1348-1352`. *(D7, D12)*

### B11. Slow DNS can add up to ~9 seconds per email
Three DNS blocklists queried serially with 3-second timeouts, no caching between messages, on the main loop. A slow resolver stalls the entire run (and feeds the C7 lock-window problem). `utils.py:391-422`. *(H6)*

### B12. The engine's IMAP connect has no timeout (the validator's does)
"Test IMAP" in Setup caps at 15s; the real filter's `connect_imap` has none — a provider that stalls the TLS handshake (the code's comments call out AOL doing this) hangs the headless run indefinitely. Validator confidence doesn't transfer to runtime. `spam_filter.py:2605-2608` vs `validators.py:60`. *(G6)*

### B13. The installer build copies *everything* in the payload folder — latent PII trap
The build does a wholesale `copytree` of `payload/MailWarden/` into the shipped app, and that same folder is the engine's runtime data root when run from the repo. One developer test-run from the repo tree would put real signals/whitelists/logs into the next public installer. The pre-build audit script checks some files but misses `memory/signals.json`, `logs/`, `false_positives/`, and runs *before* the scrubber. (Verified clean *today* — this is a trap, not an active leak. Also verified: no secrets are tracked in git; `codesign/` is properly ignored.) `app/setup_app.py:41, 63`; `scripts/audit_payload.sh`. *(S4)*

### B14. SPF "softfail" is treated as a hard failure **[MATT DECIDES]**
`softfail` + DKIM fail = deterministic auto-junk. Softfail is the *normal* result for legitimately forwarded mail and `~all` senders — this combination auto-junks legitimate forwarded mail with no AI review, and the explanation shown says the sender "was forged." Whether softfail belongs in the hard-fail set is a policy call. `utils.py:160`. *(H10)*

---

## MEDIUM (17)

| # | Finding | Where | Ref |
|---|---------|-------|-----|
| M1 | After a successful COPY to Junk, the delete-original step's result is unchecked — message ends up in BOTH Junk and inbox, and the inbox copy is never re-examined | `spam_filter.py:2914-2926` | R6 |
| M2 | Bare `EXPUNGE` in the delete/Train paths permanently destroys *other* messages the user had marked deleted in another mail client but not yet emptied | `spam_filter.py:2979, 2802` | R7 |
| M3 | No timeout/retry config on the Anthropic client; overload errors (529) aren't retried; a stuck call can stall a run for minutes; failed-call token spend never recorded | `spam_filter.py:3205, 2320-2365` | R8 |
| M4 | A second "YES" to a resolved SFID says "Not Found" — indistinguishable from a genuinely lost approval; resolved conversations are never pruned (unbounded growth feeding B3) | `spam_filter.py:4256` | T8, D10 **[MATT DECIDES on history retention]** |
| M5 | "Fwd: Re: Blacklist All" isn't recognized — a forwarded reply silently drops your command | `spam_filter.py:1237-1268` | T9 |
| M6 | Command matching is prefix-based: "Fwd: Blacklist Allister Group…" triggers Blacklist All; "Fwd: not spammy at all…" triggers False Positive | `spam_filter.py:1298` | T10 |
| M7 | Inline-forward display names get polluted with date fragments ("Apr 19, 2026 at 10:00 AM, Matt…" stored as a blocked name) | `spam_filter.py:1158` | T11 |
| M8 | Non-English mail clients' forward formats never parse — teach loop unusable in those locales | `spam_filter.py:1061-1081` | T12 **[MATT DECIDES priority]** |
| M9 | Sending-IP extraction grabs the wrong dotted-quad (HELO strings, date fragments; accepts >255 octets) — the DNSBL hard signal can check the wrong IP | `utils.py:356` | H8 |
| M10 | No IPv6 support in IP extraction — IPv6-origin mail silently skips DNSBL evaluation | `utils.py:356` | H9 |
| M11 | The learner's prompt includes ALL active refinements with no cap (the classifier caps at 25) — unbounded prompt growth, and the learner dedups against rules the filter doesn't even enforce; no contradiction detection between protect/curate rules | `learn_signals.py:1378, 833-834` | L6 |
| M12 | Saved teaching `.eml` files are never deleted — unbounded disk growth and a permanent plaintext archive of flagged mail + your typed explanations | `spam_filter.py:1305-1351` | L7 **[MATT DECIDES retention policy]** |
| M13 | The "derived from examples" counter both over- and under-counts — the number shown to users is meaningless | `learn_signals.py:1398-1430` | L8 |
| M14 | Deleted/renamed accounts leave orphaned rule scopes and permanently-trusted mail hosts (auto-seed only ever adds) | `learn_signals.py:1234-1239`, `spam_filter.py:177-225` | L9 **[MATT DECIDES cleanup behavior]** |
| M15 | Cost math ignores prompt-cache token rates; unknown model IDs silently fall back to Sonnet pricing (up to 5× off); speculative future-model prices are guesses | `spam_filter.py:612-666` | D8 |
| M16 | No config-schema migration on load — every reader must individually remember to default missing keys; one unguarded access on an upgraded config = crash | `config_io.py:154-171` | G4 |
| M17 | Account dialog saves ports unvalidated — non-numeric port = the Save button silently does nothing (error swallowed); out-of-range port saves and breaks every run | `setup_assistant.py:970-995` | G5 |

Also MEDIUM: learner stores model-derived rule text verbatim with no code-level constraint — prompt + human approval are the only guards against an over-broad "trust X" rule (S3); shipped default `signals.json` wasn't regenerated by the current scrub script — schema drift between build artifacts (L10); future-clock corruption of the cost ledger's pruning (D9).

---

## LOW (15)

| # | Finding | Ref |
|---|---------|-----|
| W1 | Synthetic dedup IDs embed the IMAP UID — UIDVALIDITY change causes re-billing for Message-ID-less mail | R9 |
| W2 | Timezone-naive timestamps: DST fall-back can freeze the schedule gate up to an hour | R10 |
| W3 | Dedup history keyed by account *display name* — renaming an account re-processes the whole inbox | R11 |
| W4 | Commands marked read before the handler runs — a mid-handler failure silently loses the command with no retry | T13, R12 |
| W5 | Duplicate "REFINEMENT" notes appended without dedup — prompt bloat on re-teach | T14 |
| W6 | Dead header plumbing (Reply-To etc. passed to a function that ignores them) | H11 |
| W7 | Integer `score=` inside X-Spam-Status could be misread | H12 |
| W8 | Learner assumes first API content block is text — legitimate response shapes fail the whole batch | L11 |
| W9 | One unparseable model response fails the entire learner batch and re-bills every tick | L12 |
| W10 | A crafted subject containing the log separator can corrupt report parsing (hide a blocked spam from the report) | D13 |
| W11 | Dashboard "Run Now" says "Filter started" even when the lock skipped the run; "--force" doesn't actually force | G7 |
| W12 | Loopback RAISE server has no auth token (worst case: window focus harassment — verified it can't do anything else) | G8, S5 |
| W13 | Pidfile PID-recycling edge case could raise the wrong app's window | G9 |
| W14 | No size cap on fetched messages — a giant email can spike memory (local-only nuisance) | S6 |
| W15 | `save_config_atomic` relies on mkstemp's default permissions rather than setting 0600 explicitly | S-hardening |

**Verified clean (worth knowing):** no secrets tracked in git (codesign properly ignored, full history checked); TLS verification on everywhere; no credentials in any log or diagnostic output; all outgoing email is plain-text (no HTML injection surface); teaching `.eml` filenames are hashes (no path traversal); version constants currently all match; UI/engine path constants currently all match; tkinter threading is done correctly; the Setup wizard leaves no partial state if quit mid-way.

---

# PART 2 — DECISIONS ONLY YOU CAN MAKE

These are queued for discussion before their fix sessions. Nothing here will be changed without your explicit per-item approval.

1. **(C1)** When a command email from your address fails authentication checks — reject silently, reject with a notice, or warn-but-honor?
2. **(C3)** What should "Dry Run" promise? Strictly nothing changes anywhere? Or "no mail moves, but teaching still works"?
3. **(B4)** Should "Yes, but…" replies auto-apply, or open a follow-up question?
4. **(C6)** Prompt-injection detectors: keep as $0 auto-junk with narrowed patterns, or downgrade to "route to the AI"? (Directly affects your AI-newsletter mail.)
5. **(B14)** Should SPF "softfail" count toward the auto-junk combination, given it auto-junks legitimately forwarded mail today?
6. **(C9)** When a user drags an email into a Blacklist folder — block on all accounts, or just that account?
7. **(C10)** Daily report: true calendar day (no gaps possible) or rolling 24 hours?
8. **(M4/D10)** Keep full signal-conversation history forever, or prune resolved ones?
9. **(M12)** Retention policy for saved teaching emails (they're a permanent archive today).
10. **(M14)** When an account is deleted, should its learned-rule scopes and trusted mail hosts be cleaned up?
11. **Spam improvements (Part 3):** the Sonnet-escalation band for borderline emails; auth-gating the domain whitelist; retiring the three over-broad default soft signals; learned-rule decay/expiry; whether new cheap signals (link mismatch, Reply-To mismatch, punycode) ever become decisive vs. advisory-only.

---

# PART 3 — SPAM IDENTIFICATION IMPROVEMENTS (summary)

The full assessment is in the audit transcript; the prioritized list, with cost math from the in-code pricing table (~$0.0043/email on Haiku today):

| Priority | Improvement | Benefit | Cost | FP risk | Size |
|---|---|---|---|---|---|
| 1 | **HTML→text fallback + ~1500-char body window** (B1) | The model finally sees real spam bodies; highest-leverage change in the audit | +$0.001–0.0015/email on AI path | None — strictly more information | S |
| 2 | **Extract body link domains into the prompt** | The #1 phishing tell; the prompt's own rules ask for it but receive nothing | +~$0.0001/email | Low | M |
| 3 | **From/Reply-To mismatch as a labeled input** | Classic BEC tell; data already parsed, never compared | negligible | Low | S |
| 4 | **Punycode (`xn--`) detection** | IDN homograph attacks; near-zero false positives | ~$0 | Very low | S |
| 5 | **Private eval corpus + precision/recall runner** | Builds a personal benchmark from your own decisions.log + taught examples; makes every future change measurable for ~$0.43/run | offline only | None | M |
| 6 | **Sonnet escalation for borderline verdicts (e.g. 0.50–0.90 spam band)** | Sharper judgment exactly where Haiku is weakest; keep Haiku default | +15–30% on AI-path spend | Reduces gray-zone error | M **[MATT DECIDES band]** |
| 7 | **Retire 3 over-broad legacy default soft signals** (the code currently suppresses them at runtime — shipping bad signals and working around them) | Fewer FPs, removes a workaround | $0 | Reduces FP | S **[MATT DECIDES]** |
| 8 | **Auth-gate the domain whitelist** (today a spoofed whitelisted sender skips ALL checks) | Closes a real spoof bypass | $0 | A rare unauthenticated-but-legit sender goes to AI instead of auto-pass | M **[MATT DECIDES]** |
| 9 | **Surface match counts / decay for learned rules** (recorded but never used) | Stale rules stop misleading the model | ~$0 | Reduces FP | M |
| 10 | **FP→learned-rule correction linkage** (today a misfiring approved rule has only a manual fix) | Self-healing teach loop | varies | Reduces FP | M-L |

Also noted: the model only sees the first 3 Received hops (origin hop is dropped); attachment names/types are parsed but never surfaced; the `tests/_out` baselines were generated by an older build and should be regenerated before being trusted.

**Model choice verdict:** Haiku 4.5 as default is correct — don't move off it. Sonnet only as a borderline-escalation tier. Opus is not worth it for binary classification with this prompt.

---

# PART 4 — FIX-SESSION PROMPTS

Each block below is one Claude Code session. Run them in order — Session 1 reduces risk for everything after it. Every prompt builds in your rules: plan first, wait for go-ahead, no business-logic changes without asking, verify in the running app, check the diff.

**Model guide:** *Fable 5 at effort xhigh* for the five riskiest sessions — **1 (locking), 2 (command authentication), 3 (forward parsing), 5 (authentication parsing), and 9 (daily report)** — where the bugs involve concurrency, security, or subtle parsing. *Sonnet 4.6 at effort high* for everything else (well-scoped fixes with reproduction cases; cheaper and fully capable). Sessions estimated at one sitting each.

**Two rules that apply to EVERY fix session:**

1. **Test-first.** Before fixing each finding, write a failing test that reproduces it using the audit's reproduction inputs (Part 1 cites them). The fix is done when that test passes and the rest of the suite still passes. For race conditions where a unit test isn't feasible, the session must state how the fix was verified instead.
2. **Independent review gate.** After each fix session finishes, do NOT move on. Start a fresh session and paste the review prompt below. The reviewer reports only — any problems it finds go back to a new fix session. This catches both "claimed fixed but isn't" and "fix for X broke Y," regardless of which model did the fixing.

> **Review-gate prompt** *(fresh session after every fix session — Sonnet 4.6, effort high; fill in the session number)*
>
> Read AUDIT-2026-06-11-bug-report.md, Part 4. Fix Session ___ just completed in this repository, claiming to fix the findings listed in that session's prompt. You are an independent reviewer — do not trust the previous session's claims. Using git diff/git log, review every changed line against each claimed finding: (1) confirm each fix actually addresses the audited behavior, checking against the audit's reproduction inputs; (2) hunt for NEW bugs introduced by the changes, especially in adjacent code the diff touches; (3) confirm the new tests genuinely exercise the bug (they should fail if the fix were reverted); (4) run the full test suite and report the real output. Give me a plain-English PASS or FAIL verdict per finding, plus anything new you found. Do not fix anything — report only.

---

### Session 1 — Shared file locking + save-as-you-go *(Fable 5, effort xhigh, plan mode)*
> Read AUDIT-2026-06-11-bug-report.md, finding C7 and B7, and the two rules at the top of Part 4 (test-first, review gate). Build one shared cross-process file-lock helper (flock-based, like the learner's existing single-instance lock) and apply it to every read-modify-write of signals.json, pending_signals.json, whitelist.json, blacklist.json, token_usage.json, processed_ids.json, and config.json across spam_filter.py, learn_signals.py, daily_report.py, config_io.py/dashboard.py, and menu_bar.py. Replace the mtime-based filter lock in app_entrypoint.py (_acquire_filter_lock) with a real flock that checks holder liveness and doesn't fail open. Also make the learner stop rewriting all of config.json for one timestamp (store last_scan elsewhere or re-read-merge under lock), and make spam_filter.py persist processed_ids and token_usage incrementally (per account at minimum) instead of once at run end. Before each fix, write a failing test that reproduces the lost-update (simulated concurrent writers where feasible). No business logic changes anywhere — this is purely about which process wins a write. Plan first and wait for my go-ahead. Run the test suite, then verify with a live filter run + dashboard open simultaneously. Check the diff line by line before declaring done.

### Session 2 — Authenticate owner commands *(Fable 5, effort xhigh, plan mode; discuss Decision #1 first)*
> Read AUDIT-2026-06-11-bug-report.md, findings C1 and B3 (refs T3/S1/S2/T4). First, discuss with me in plain English what should happen when a genuine command from my address fails SPF/DKIM/DMARC — do NOT implement until I decide. Then: wire utils.summarize_authentication into _command_sender_is_owner so commands and SFID approvals are honored only with my decided policy; make SFIDs unguessable (random token) and fix the count-based sequence collision in both generate_sfid and learn_signals.next_sfid; make a second reply to a resolved SFID say "already applied" instead of "Not Found". Plan first, wait for go-ahead, run tests, verify by sending real command emails (one authenticated, one simulating failure), check the diff.

### Session 3 — Forward-parsing safety *(Fable 5, effort xhigh, plan mode)*
> Read AUDIT-2026-06-11-bug-report.md, finding C2 plus M5, M6, M7 (refs T1, T2, T9, T10, T11). Fix parse_forwarded_email and detect_email_command in spam_filter.py so that: (1) command handlers cross-check the body-extracted "original sender" against the outer envelope and never act on an address embedded in a fake forward block without surfacing the discrepancy; (2) an inline-forward attribution line whose address is one of MY OWN identities is never treated as the spam sender; (3) "Fwd: Re: <command>" is recognized; (4) command matching is anchored so "Blacklist Allister…" no longer triggers "Blacklist All"; (5) inline display names stop absorbing date fragments. docs/research/forward-format-parsing-v2.md has the format research. These are correctness fixes, not behavior changes — but if any fix would change what a command does, stop and ask me. Plan first, wait for go-ahead, extend tests/test_fixes.py with reproduction cases for each, verify with real forwarded emails, check the diff.

### Session 4 — Make Dry Run truly dry *(Sonnet 4.6, effort high; discuss Decision #2 first)*
> Read AUDIT-2026-06-11-bug-report.md, finding C3 (refs R1, D14). FIRST, discuss with me in plain English what Dry Run should promise — list every side effect that currently still happens (Train-folder permanent deletion, marking read, list/signal writes, confirmation emails, learner spawn, report wording) and wait for my per-item decisions. Then implement exactly what we agreed, including the daily report's dry-run wording. Run tests, verify with a live dry-run pass, check the diff.

### Session 5 — Authentication-parsing fixes *(Fable 5, effort xhigh, plan mode)*
> Read AUDIT-2026-06-11-bug-report.md, findings C5, B5, B6, M9, M10 (refs H2, H7, H5, H1, H8, H9). In utils.py and spam_filter.py: (1) correlate each DKIM header.d with its own pass/fail result instead of harvesting all domains when any pass exists; (2) read all Authentication-Results headers and select by authserv-id instead of first-only; (3) strip trailing dots in parse_from_address/extract_domain; (4) unify the two From-parsers so lists, AI prompt, and brand-match see one canonical sender; (5) fix _extract_sending_ip to take only the bracketed connecting IP, validate octet ranges, and handle IPv6. Do NOT change which signals are hard vs soft (that includes the softfail question — leave it; it's queued for a separate decision with me). Extend tests/test_fixes.py with the reproduced attack inputs from the audit. Plan first, wait for go-ahead, run tests, check the diff.

### Session 6 — Prompt-injection detector recalibration *(Sonnet 4.6, effort high; discuss Decision #4 first)*
> Read AUDIT-2026-06-11-bug-report.md, finding C6 (refs H3, H4). FIRST show me, in plain English, each detector pattern and the reproduced false positives (AI newsletters, chat transcripts, marketing-SaaS copy), and the options: narrow the patterns, require structural context, or downgrade from $0 auto-junk to routing to the AI. Wait for my per-pattern decisions — this changes what gets filtered. Then implement, add the false-positive examples as regression tests, run tests, check the diff.

### Session 7 — The classifier sees the real email *(Sonnet 4.6, effort high)*
> Read AUDIT-2026-06-11-bug-report.md, finding B1 and Part 3 items 1-4 (HTML fallback, link domains, Reply-To mismatch, punycode, plus origin Received hops and the JSON-salvage parse fallback). Implement these as ADVISORY prompt inputs only — none of them may auto-junk or change the decision pipeline; the model just gets more labeled information. The HTML→text fallback should reuse the existing html_to_text. If anything would alter precedence or thresholds, stop and ask me. Add tests including the HTML-only McAfee fixture proving the body now reaches the model, run the corpus runner (note: live API key, ~$0.05), check the diff.

### Session 8 — Reply understanding *(Sonnet 4.6, effort high; discuss Decision #3 first)*
> Read AUDIT-2026-06-11-bug-report.md, finding B4 (refs T6, T7). FIRST discuss with me: should "Yes, but…" auto-apply or open a follow-up? Then fix classify_reply: word-boundary matching so "noted…" stops reading as NO, and implement my decision for qualified approvals. Add the audit's reproduced phrasings as tests, run tests, check the diff.

### Session 9 — Daily report correctness *(Fable 5, effort xhigh, plan mode; discuss Decisions #6, #7, #8 first)*
> Read AUDIT-2026-06-11-bug-report.md, findings C9, C10, B9, B10 plus M15, W10 (refs D1, D4, D6, D7, D8, D12, D13). FIRST get my decisions on: report window semantics (calendar day vs rolling), folder-drag blacklist scope (global vs per-account), and conversation-history retention. Then: implement the decided window with a persisted watermark; make the folder sync schema-aware so it can't crash on scoped entries or lose drags; add decisions.log rotation and stop full-file reads; add a last-successful-report watermark surfaced in the menu bar; add SMTP retry; account for cache tokens in cost math; sanitize newlines/separators out of logged subjects. Remove the report's write of token_usage.json (it should be read-only — coordinate with Session 1's locking). Plan first, wait for go-ahead, run tests, verify a real report run, check the diff.

### Session 10 — Dashboard & config fixes *(Sonnet 4.6, effort high)*
> Read AUDIT-2026-06-11-bug-report.md, findings C4, B2, M16, M17, W11 (refs G1, G2, G4, G5, G7). Fix: (1) the confidence-threshold key mismatch so the slider actually controls the filter — pick ONE location, migrate the other, and align app_entrypoint/dashboard reads; (2) Setup Assistant must load-and-merge existing config, never start from defaults over an install; (3) add a single DEFAULT_CONFIG deep-merge migration in load_config; (4) validate ports on save like the test button already does; (5) make Run Now report honestly when the lock skipped the run. No business-logic changes — these restore intended behavior. Run tests, then verify in the running app: move the slider, confirm via a filter run that the engine uses the new value. Check the diff.

### Session 11 — Learner robustness *(Sonnet 4.6, effort high)*
> Read AUDIT-2026-06-11-bug-report.md, findings C8, B8, M11, M13, W8, W9 (refs L2, L4, L6, L8, L11, L12). Fix: (1) sanitize Received headers (and the learner-path user_explanation) with _sanitize_learner_delimiter like every other untrusted field; (2) fix the last_scan race so examples saved during a learner run aren't skipped (snapshot scan-start time or mark files processed); (3) cap the learner's refinement context to match the classifier's 25; (4) make derived_from_examples count correctly; (5) handle non-text first content blocks and salvage JSON from prose; isolate per-example failures so one bad response doesn't fail the batch. Retention policy for .eml files (M12) is NOT in scope — it's queued for a decision with me. Run tests (test_phase1a.py covers learner behavior), check the diff.

### Session 12 — IMAP runtime safety *(Sonnet 4.6, effort high)*
> Read AUDIT-2026-06-11-bug-report.md, findings M1, M2, M3, B11, B12, W1, W2, W3, W4 (refs R6, R7, R8, H6, G6, R9, R10, R11, R12, T13). Fix: check the STORE result in move_to_junk and report failure honestly; use UID EXPUNGE instead of bare expunge in the delete and Train paths; set explicit timeout and retry policy on the Anthropic client and retry 529s; add a timeout to connect_imap matching the validator; cache DNSBL results per run and parallelize or shorten the lookups; drop the IMAP UID from synthetic dedup IDs; use monotonic/UTC time for the interval gate; key processed_ids by account username instead of display name (with a one-time migration of existing buckets); mark command emails read only after the handler succeeds. No behavior/policy changes. Run tests, do a live filter run, check the diff.

### Session 13 — Build & packaging hygiene *(Sonnet 4.6, effort medium)*
> Read AUDIT-2026-06-11-bug-report.md, findings B13 and L10 (refs S4, L10). Change setup_app.py from copytree-everything to an explicit allowlist (src/*.py, EULA.md, LICENSE, requirements.txt, blacklist/skip_names.txt); extend scripts/audit_payload.sh to hard-fail on memory/, logs/, false_positives/, or stray JSON under payload; move the audit after scrub_signals.py in build_installer.sh; regenerate the shipped default signals.json with the current scrubber so the schemas match. Verify by running a full build and inspecting the produced bundle's file list. Check the diff.

### Session 14 — Private eval corpus *(Sonnet 4.6, effort high; brainstorm first)*
> Read AUDIT-2026-06-11-bug-report.md, Part 3 item 5. This is a new feature, so start with a short plain-English design conversation: a "Build my eval set" capability that assembles a private, local-only labeled corpus from decisions.log, taught spam examples, and False-Positive forwards, plus a before/after runner wrapping classify_eml_offline that reports precision/recall in plain English (~$0.43 per 100-email run). Walk me through the labeling rules (especially "presumed legit") and wait for approval before building. Also regenerate the stale tests/_out baselines while you're in there.

### Sessions 15+ — Spam-improvement decisions *(discussion first, then Sonnet 4.6 high per item)*
> Read AUDIT-2026-06-11-bug-report.md, Part 3 items 6-10 and Part 2 item 11. One at a time, walk me through: the Sonnet escalation band for borderline verdicts (with the cost math), auth-gating the domain whitelist, retiring the three over-broad default soft signals, learned-rule decay/expiry, and the FP→learned-rule correction path. Each changes what the filter does — full plain-English discussion of implications before any code. Implement only what I approve, measured against the eval corpus from Session 14.

---

## Suggested overall order and why

1. **Session 1 (locking)** — it's the foundation; several later fixes write to the same files and shouldn't be built on the race-prone base.
2. **Sessions 2 + 3 (command auth, forward parsing)** — the active security/poisoning exposure.
3. **Session 10 (threshold slider, setup overwrite)** — user-facing controls that don't work.
4. **Sessions 5 + 6 (auth parsing, injection detectors)** — classification correctness, including the false-positive risk to your own mail.
5. **Session 7 (classifier inputs)** — biggest detection-quality lift.
6. **Sessions 4, 8, 9, 11, 12, 13** in any order.
7. **Session 14, then 15+** — measurement before tuning.

---

## Appendix — methodology

Eight parallel read-only agents (Opus-class) audited: IMAP runtime/concurrency (refs R*), teach/approve loop (T*), header heuristics (H*), signal learner (L*), daily report/accounting (D*), GUI/config layer (G*), security (S*), and spam-detection quality. Findings marked "reproduced" were verified by executing the actual functions against crafted inputs in the project's test environment. Cross-agent duplicates were merged (the lost-update race was independently found by five agents — strong signal it's the #1 structural issue). Total subagent spend: ~1.9M tokens. No files were modified during the audit other than the creation of this report.

---

# PART 5 — FIX SESSION STATUS *(update this section at the end of every fix session)*

**Testing reality:** the app cannot run on the development machine. "Verified live" requires building an installer and running it on Matt's M1. To minimize builds, live checks are batched across sessions; each session records below exactly what is and is not yet verified.

## Session 1 — Shared file locking + save-as-you-go (completed 2026-06-11)
**Status: COMPLETE — test suite green. Independent review gate: PASSED (2026-06-11, fresh-session reviewer). Live verification: PENDING (no installer built). Committed on `calibration-security-build1`.**

**What was built** (C7, B7, plus one approved scope addition: decisions.log appends — D5):
- New shared lock helper `file_lock.py` (flock-based, fail-closed, crash-safe via OS auto-release, deadlock-free multi-file ordering), byte-identical copies in the engine tree (`payload/MailWarden/src/`) and app tree (`app/mailwarden_app/`), with a test that fails if the two copies ever drift.
- Every read-modify-write of signals.json, pending_signals.json, whitelist.json, blacklist.json, token_usage.json, processed_ids.json, and config.json across spam_filter.py, learn_signals.py, daily_report.py, config_io.py, dashboard.py, menu_bar.py, setup_assistant.py, and app_entrypoint.py now runs under the lock (long-running processes use a locked re-read-merge instead of holding locks). decisions.log appends are locked too.
- The mtime-based filter lock was replaced with a real flock: no 10-minute staleness window, OS-level holder liveness, never fails open. All three lock-status readers (menu bar, Dashboard, entrypoint) updated in lockstep.
- The learner no longer writes config.json at all — `last_scan_timestamp` moved to a new `memory/learner_state.json` (with a one-time fallback read from config so existing installs don't re-scan and re-bill old teaching examples). The filter's EULA-tracking write became a locked re-read-merge that touches only that field.
- Save-as-you-go (B7): the filter persists processed_ids and token_usage after EVERY account (token_usage as a delta merge so concurrent learner/report writes survive), plus a final flush. A crash or sleep mid-run now loses at most the in-progress account.

**Verified on the dev machine (no running app required):**
- Full pytest suite: **219 passed, 0 failed** (186 pre-existing + 33 new locking tests in tests/test_locking_core.py, test_locking_engine.py, test_locking_app.py).
- Failing-first reproductions captured for: L1 (learner blind-save erasing an approved/deleted refinement), L3 (learner config rewrite reverting a concurrent settings save), L5/R4/D2 (token-spend erasure), the EULA config clobber, R3 (the old "lock" not actually locking), and raw cross-process lost updates (unlocked writers lost 50% of updates; locked lost none).
- An independent internal QA diff review (line by line, both trees): PASS on all areas; zero business-logic drift; deliberately-out-of-scope items confirmed untouched (C9 folder-sync crash, B2 setup overwrite, W11 Run-Now honesty, B8 timestamp semantics, C4 threshold key name).

**NOT yet verified (needs an installer on the M1 — batch with later sessions):**
1. Live filter run with the Dashboard open: a list entry added in the Dashboard mid-run survives the run's end.
2. A second run triggered during a long run cleanly skips, and the menu-bar/Dashboard lock status reads correctly.
3. A Dashboard settings change made during a learner run survives the learner finishing.
4. processed_ids.json / token_usage.json visibly update during a run (per account), not only at the end.
5. Normal end-to-end smoke: scheduled runs, teach commands, learner proposals, daily report — all behave as before.

**Known follow-ups (not defects in this session):**
- `.lock` sidecar files under `payload/MailWarden/memory/` are not matched by .gitignore and would be shipped by the build's copytree — fold into Session 13 (B13).
- Three empty `.lock` sidecars were created in `~/MailWarden/memory/` on the dev machine during testing (harmless — the installed app creates these legitimately at runtime; verified no data files were touched).
- Two reviewed-and-approved deviations from the original Session 1 prompt: the filter's pending_signals saves are a true re-read-merge (a plain lock could not fix T5, because the filter saves a run-start snapshot repeatedly), and the daily report's "Last ran" line now reads learner_state.json with config fallback (it would otherwise have silently frozen when the learner stopped writing config).

**Next step:** Session 2 (command authentication, audit Part 4) in a fresh session — it begins with a plain-English discussion of Decision #1 before any code. Live checks for Session 1 remain queued in the list above for the next installer build.

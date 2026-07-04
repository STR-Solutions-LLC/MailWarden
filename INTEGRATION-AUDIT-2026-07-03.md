# MailWarden Integration Audit — 2026-07-03

Commit audited: `516692f` (branch `calibration-security-build1`).
Scope: combined live behavior across the reply-command corridor, learner lifecycle,
cross-feature interactions (sender-history × safe-sender-approval × F5 attribution ×
item-(b) rule review × cascade), dashboard/report views, and a codebase-wide sweep of
the "ack-before-verify" and "rigid-regex on LLM output" disease classes.
All line numbers refer to `payload/MailWarden/src/` unless another path is given.
Findings are ordered most severe / hardest first.

---

## 1. Learner proposal emails are auto-REJECTED by the filter's next tick (self-loop guard bypass)

**Files/lines:** `learn_signals.py:1201-1211` (`_send`/`_build_msg` — no `X-MailWarden-System`
header), `learn_signals.py:1441-1481` (proposal body copy), `spam_filter.py:6008-6030`
(loop-top guard), `spam_filter.py:7180-7193` (`_own_prefixes`), `spam_filter.py:2848-2886`
(`classify_reply`), `spam_filter.py:7490-7517` (negative → rejected).

**Root cause — three guards all miss:**
1. `spam_filter.send_email` stamps `X-MailWarden-System: 1` (line 1663); the learner's own
   `_send()` does NOT. So the learner's `[SFID-...] Proposed refinement — ...` email is not
   caught by the loop-top own-mail guard.
2. The SFID branch's `_own_prefixes` guard expects the body to start with
   `"MailWarden analyzed your forwarded spam example"`, but the learner's actual body starts
   `"MailWarden analyzed the spam example you submitted and proposes a ..."`. Both strings were
   introduced in the same commit (`34ceb39`, v1.6.0-beta.12) already mismatched.
3. The empty-reply fallback (`not reply_text_check`) doesn't fire because the proposal body is
   full of unquoted text.

**Concrete failure scenario:** Owner drops a spam into Train MailWarden (or forwards
`Fwd: SPAM Example`). Learner creates the pending conversation and emails the proposal to the
owner's polled inbox. On the next filter tick (≤15 min) the filter fetches that UNSEEN email:
subject matches `[SFID-...]`; sender = the owner's own SMTP from-address → passes the S2 owner
check (`_owner_identities` includes SMTP identities, 2482-2502) AND the auth gate (authenticated
submission through the owner's own server). `is_our_own_email` is False (prefix mismatch, body
non-empty). `classify_reply()` runs on the proposal body, which contains the literal HOW-TO-REPLY
lines `"NO — reject."` and `"WITHDRAW"` → `_NEGATIVE_PHRASES` ("no", "reject", "withdraw") match →
classification `"negative"` → the conversation is marked **rejected**, a
"The refinement proposal has been rejected [SFID-...]" email is sent, and the owner's later real
YES gets "This was already declined." Every emailed learner proposal is destroyed one tick after
it is sent. (The FP-analysis email path is NOT affected — it is sent via `spam_filter.send_email`
and its body first line is in `_own_prefixes`.)

**Fix direction:** Stamp `X-MailWarden-System: 1` in `learn_signals._build_msg`; also align the
`_own_prefixes` entry with the real body copy (belt and suspenders for already-delivered mail).
Verify live on the M1 after deploy.

**Complexity: simple** (two one-line changes) — but top severity; ship first.

---

## 2. `persist_pending_merge` clobbers concurrent Dashboard resolutions and resurrects withdrawn proposals

**Files/lines:** `spam_filter.py:1584-1613` (`persist_pending_merge`),
`spam_filter.py:5869` (run-start snapshot), `app/mailwarden_app/config_io.py:502-686`
(`apply_refinement_from_pending`, `reject_pending`, `withdraw_pending`),
`daily_report.py:789-815` (`expire_pending_signals`).

**Root cause:** The merge overlays **every** conversation in the filter's run-start snapshot onto
the fresh file ("filter's version wins"), and re-appends any snapshot conversation missing from
the fresh file. Its correctness argument only covers the learner ("only ever ADDS conversations").
It ignores the Dashboard and the daily report, which are concurrent **resolvers/deleters** of the
same file.

**Concrete failure scenarios:**
- Filter run starts (loads pending; conv X `awaiting_reply`). Mid-run the owner clicks Approve in
  Dashboard → X becomes `approved` on disk and the refinement activates in signals.json. The filter
  then handles any other SFID/FP event and calls `persist_pending_merge` → the stale
  `awaiting_reply` copy of X **overwrites** the approved record. X reappears as pending in the
  Dashboard and the daily report; a second approval "re-applies" (skip-add) — state divergence and
  confusing double-acks.
- Owner clicks **Withdraw** in Dashboard (conversation removed from disk). The filter's merge
  re-appends the stale copy ("filter-created proposal" branch) — the withdrawn proposal is
  resurrected.
- `expire_pending_signals` (daily report) marks a conv expired mid-filter-run; the merge reverts it
  to `awaiting_reply`.

**Fix direction:** Track exactly which conversation ids the filter mutated this run and overlay
only those; treat a conversation missing from the fresh file as deleted (never re-append unless the
filter itself created it this run).

**Complexity: complex** (concurrency semantics across three writers; needs careful tests).

---

## 3. F5 rule attribution likely silently inert: model told to echo "bracketed identifiers", whitelist compares unbracketed

**Files/lines:** `spam_filter.py:3413-3420` (`_ATTRIBUTION_INSTRUCTION`),
`spam_filter.py:3451-3458` (`emit` — `injected_ids` holds bare `R-...` ids, prompt lines show
`[R-...]`), `spam_filter.py:8071-8074` (whitelist filter), `spam_filter.py:4499-4501`
(`_validate_classification` passes strings through unchanged).

**Root cause:** The prompt instructs: *"include a field `matched_rules` whose value is a JSON array
of the **exact bracketed identifiers**"*. A model that complies literally returns
`["[R-20260701-ab12]"]`. The log-time whitelist is `rid in account_injected_ids` where
`account_injected_ids` contains bare `R-20260701-ab12` — bracketed echoes never match and are
silently dropped. No normalization anywhere.

**Concrete failure scenario:** A learned R- rule drives a junk verdict; the model echoes the id in
brackets; the `RULE IDS:` line is never written to decisions.log →
`parse_decisions_24h` finds no `rule_ids` → the APPROVE token entry carries `rule_ids: []` → an
owner rescue never enqueues the rule → the whole item-(b) LEARNED-RULE REVIEW section never appears.
The feature chain fails silently end-to-end. The offline eval cannot catch this: attribution is
structurally OFF in the eval configuration (zero ai_refinements keeps prompts byte-identical).

**Fix direction:** Normalize before whitelisting (`rid.strip().strip("[]")`), and/or reword the
instruction to "the identifier text without brackets". Then verify once against live model output
(check a decisions.log record for a `RULE IDS:` line after a learned-rule junk).

**Complexity: simple** (one-line normalization) — but requires live verification either way.

---

## 4. SFID and MWR reply handlers mark `\Seen` BEFORE the handler completes — a mid-handler exception silently destroys the owner's reply

**Files/lines:** `spam_filter.py:7200-7204` (SFID: `mark_uid_seen` up front),
`spam_filter.py:7649-7651` (APPROVE), `spam_filter.py:7764-7765` (KEEP/DROP),
`spam_filter.py:8099-8101` (account-level catch), `spam_filter.py:5117-5131`
(`fetch_unseen_uids` — UNSEEN only), contrast `spam_filter.py:6093-6102` (W4 `_finalize_command`
discipline used by the subject commands).

**Root cause:** The subject-command handlers got the W4 fix (finalize only after completion), but
the three reply branches still mark the message `\Seen` at the top. If anything in the handler
raises after that (e.g. `persist_pending_merge`/`apply_signal_changes` I/O error,
`append_refinement_log` on a full disk, `conv["conversation_history"]` KeyError on a record missing
that key at 7244, `add_approved_domain` raising when `memory/` is missing), the account-level
`except` at 8099 eats it — the message is `\Seen` but NOT in processed_ids, so the next tick's
UNSEEN search never returns it. The owner's YES/NO/APPROVE/DROP is gone forever with no ack and no
retry. This is the same disease class as the shipped ack-before-verify bug, on the mark-seen axis.

**Fix direction:** Move `mark_uid_seen` to each branch's success exit (pair it with
`_record_processed`, exactly like `_finalize_command`), accepting the small risk of a duplicate ack
on a crash between apply and mark (the resolved-conversation guard already answers replays
honestly).

**Complexity: moderate** (touch three branches; reason about the resend-vs-drop tradeoff per verb).

---

## 5. FP-teach and follow-up API failures are swallowed: message finalized, owner gets nothing

**Files/lines:** `spam_filter.py:6275-6356` (FP branch: `except` at 6350 logs, then
"Mark as processed regardless" → `_finalize_command()`), `spam_filter.py:7540-7573` (follow_up:
`except` logs, then falls to `_record_processed` at 7575).

**Root cause:** Both paths treat an Anthropic API failure (rate limit burst, network outage) as
terminal AND successful-enough: the message is marked seen + processed so it is never retried, and
**no email of any kind** is sent to the owner. Contrast the SPAM Example handler (7112-7117), which
at least emails an error body on failure.

**Concrete failure scenario:** Owner forwards `Fwd: False Positive` during a rate-limit window.
All three `client.messages.create` attempts fail. The forward is consumed silently: no analysis
email, no pending conversation, no retry. The owner assumes MailWarden is analyzing and waits for
an email that never comes. Same for a follow-up question on an open SFID: the question is appended
to conversation_history but never answered.

**Fix direction:** On API failure either (a) leave the message UNSEEN/unprocessed so the next tick
retries (mirrors the classification-failure contract at 8028-8032), or (b) send an honest "could
not analyze right now, will not retry — please re-forward" ack. Pick one; today it is neither.

**Complexity: simple.**

---

## 6. APPROVE-rescue of a blacklist / subject-keyword / pre-classifier junk is a no-op acked as a rescue (and blacklisted mail is double-listed)

**Files/lines:** `daily_report.py:963-1012` (`parse_decisions_24h` — any entry with "MOVED to"
becomes a numbered spam entry, including `DECISION: BLACKLISTED`, `BLOCKED (subject keyword)`, and
pre-classifier `SPAM` records), `daily_report.py:1156` (APPROVE copy: "MailWarden will stop junking
that sender's domain"), `spam_filter.py:7684-7703` (ack), `spam_filter.py:7840-7924` (blacklist and
subject-keyword checks run BEFORE classification), `spam_filter.py:7946-7992` (pre-classifier),
`spam_filter.py:4044-4061` (approved domains affect ONLY the AI prompt).

**Root cause:** `approved_senders.json` is consumed exclusively by the classifier prompt
(OWNER-APPROVED SENDER block / RULE 0). Deterministic junking paths — blacklist address/name,
subject keyword, pre-classifier hard signals — never consult it. But all of those entries appear in
the report's numbered junk list and in the APPROVE token map, and `add_approved_domain` happily
returns True.

**Concrete failure scenario:** A sender the owner once blacklisted (or one that trips a DNSBL hard
signal) appears as item 3. Owner replies `APPROVE 3`. Ack: "Approved: dom … MailWarden will stop
junking that sender's domain." Next email from that domain is junked again by the blacklist before
the classifier ever sees the approval. The owner's explicit instruction silently does nothing,
forever. Secondary: blacklisted entries are ALSO rendered in the report's BLACKLIST ACTIVITY
section, so they are listed (and counted in "Emails evaluated"/"Spam moved") twice.

**Fix direction:** Either exclude deterministic-block records from `numbered_spam_entries` /
`build_approval_entries`, or make the APPROVE handler detect a blacklist/keyword-driven entry and
ack honestly ("this sender is on your blacklist — reply/forward 'Remove from Blacklist' instead"),
optionally offering the removal.

**Complexity: moderate** (a product-copy decision Matt should make; mechanics are easy).

---

## 7. block_sender_proposal YES branch: ack-before-verify (known finding (a) — CONFIRMED, still live)

**Files/lines:** `spam_filter.py:7332-7368` (YES branch), `spam_filter.py:811-844`
(`add_blocklist_entry_local` returns False on empty value / bad kind — return value ignored).

**Root cause:** `add_blocklist_entry_local(entry.get("value",""), ...)`'s boolean result is
discarded; the conversation is unconditionally marked `approved` and the owner is acked
"Sender blocked … Added domain " (empty value renders as blank). A structurally empty/corrupt
`blocklist_entry` (hand-edited store, partial write, future producer bug) destroys the proposal
while acking success — exactly the shipped FP-teach disease. Contrast the Dashboard path, which
pre-validates `entry.get("value")` before applying (`config_io.py:607-609`).

**Fix direction:** Mirror the spam_example_proposal guard added in `29a7c42`: validate
`entry["value"]`/`kind` first; on failure keep the conversation pending, log `apply_failed`, send
the honest "could not apply" ack. Also check the returned bool.

**Complexity: simple.**

---

## 8. `apply_ai_refinement` is still ack-blind — and a RETIRED rule id is acked as "applied and now active" while staying retired

**Files/lines:** `spam_filter.py:2965-3013` (`apply_ai_refinement` — always returns a description;
logs event "applied" even on the skip branch), `spam_filter.py:2977-2980` (`existing_ids` includes
retired records — status not checked), `spam_filter.py:7408-7425` (email ack "now active"),
`app/mailwarden_app/config_io.py:536-539` + `dashboard.py:2913-2916` (same pattern: id exists → no-op,
conv resolved, dialog "Refinement … is now active").

**Root cause (known finding (b), expanded):** The function cannot report failure, and its duplicate
check treats ANY existing id — including `status: "retired"` (item-(b) DROP) — as "already active".

**Concrete failure scenario:** Owner DROPs rule R-x via a report reply (status → retired). A stale
pending proposal carrying the same R-x id (e.g. resurrected by finding #2, or an old unanswered
email the owner finally answers YES) is approved. `apply_ai_refinement` skips the add, logs
"applied", and the owner is told "The refinement has been applied and is now active in the filter"
— while the rule remains retired and excluded from every prompt. Same lie from the Dashboard path.

**Fix direction:** Return a (applied: bool, desc) result; distinguish "already active" /
"exists but retired" / "added"; ack each honestly (retired → offer to re-activate, which is the
only un-retire path that exists — see finding 10).

**Complexity: simple-moderate** (signature change ripples to 3 call sites).

---

## 9. The report's PENDING SIGNAL REVIEWS section invites a reply the corridor cannot route

**Files/lines:** `daily_report.py:847-851` ("[SFID-x] … Reply YES to apply, NO to reject, or ask a
question."), `spam_filter.py:7128` (SFID routing is subject-regex only),
`spam_filter.py:7644-7838` (MWR branch: APPROVE/KEEP/DROP or fall through to classification).

**Root cause:** The daily report renders pending SFID proposals with "Reply YES to apply." An owner
who replies **to the report** produces subject `Re: MailWarden Report — … [MWR-token]` — no
`[SFID-...]` anywhere, and the SFID resolver only reads the subject. The reply parses as neither
APPROVE nor KEEP/DROP, falls through to normal classification, and is silently ignored (no ack,
no error). The proposal later expires "without response."

**Fix direction:** Change the report copy to "reply to the proposal email itself (subject contains
the SFID)", or teach the MWR branch to resolve a bare YES/NO against the report's listed pending
SFIDs when exactly one is pending (needs a design decision).

**Complexity: simple** for the copy fix; moderate for routing.

---

## 10. DROP ack promises reversibility that has no mechanism: "reply and let us know if you want it back"

**Files/lines:** `spam_filter.py:7805-7812` (DROP ack copy), `spam_filter.py:547-572`
(`retire_ai_refinement` — retire only, no un-retire anywhere), `config_io.py:410-413`
(`list_active_refinements` filters to active → retired rules invisible in the Dashboard),
`dashboard.py:2688-2706` (active list is the only refinement management surface).

**Root cause:** The ack to a DROP says the retirement "is reversible — reply and let us know if you
want it back." A reply to that ack carries the `[MWR-token]` subject, parses as no command, and is
silently classified as ordinary mail. There is also no GUI path: retired refinements are excluded
from every Dashboard view, and no code anywhere flips `retired` back to `active`. The only real
un-retire is hand-editing signals.json.

**Fix direction:** Either remove the promise from the copy (fast), or add an `UNDROP n` /
`RESTORE n` verb to the MWR parser plus a retired-rules section in the Dashboard.

**Complexity: simple** (copy) / **moderate** (real restore path). Matt must choose.

---

## 11. HTML-only and bottom-posted owner replies are silently swallowed as "our own email"

**Files/lines:** `spam_filter.py:2936-2948` (`extract_reply_text` — quoted-line strip + hard break
at "On … wrote:"), `spam_filter.py:4200-4216` + 4420 (`plain_text_body` has NO html fallback),
`spam_filter.py:7190-7198` (SFID: empty reply → `is_our_own_email` → record processed, no reply),
`spam_filter.py:7634-7642` (MWR: empty reply → skip, record processed).

**Root cause:** Reply extraction reads only the `text/plain` part and stops at the attribution
line. Two real client behaviors defeat it: (a) an HTML-only reply (no text/plain alternative —
some webmail/corporate clients) yields an empty `plain_text_body`; (b) a bottom-posting owner puts
YES **after** the "On … wrote:" line, which `extract_reply_text` cuts. Both produce an empty reply
→ classified as MailWarden's own email → recorded processed with **no feedback of any kind**, and
the proposal eventually expires. The owner did exactly what the email asked and was ignored.

**Fix direction:** Fall back to `html_to_text(html_body)` when the plain part is empty (the helper
already exists and is hardened); don't break at "On … wrote:" until at least one non-empty reply
line has been seen. When the reply still parses empty in the SFID/MWR branch, send a short "I
couldn't read your reply — please reply with YES or NO above the quoted text" ack instead of
silence.

**Complexity: moderate.**

---

## 12. Dry-run SPAM is re-classified (re-billed) every tick and permanently poisons sender-history counts

**Files/lines:** `spam_filter.py:8076-8093` (dry-run SPAM deliberately not cached),
`spam_filter.py:5982-6005` (UNSEEN fetch → processed check), `daily_report.py:980-1012`
(each duplicate log record becomes another numbered report entry),
`spam_filter.py:3799-3885` (`build_sender_history_index` counts every `DECISION: SPAM` record).

**Root cause:** In dry run, a SPAM verdict is neither moved, marked seen, nor cached in
processed_ids (intentional, so it is acted on after dry-run turns off). But the message therefore
remains UNSEEN and uncached, so **every subsequent tick re-fetches and re-classifies it** (1-2 API
calls per tick in cascade mode) and appends another `DECISION: SPAM` record.

**Concrete failure scenario:** Fresh installs default `dry_run: true`. One unread spam sitting in
the inbox for 24 h at the 15-min interval ≈ 96 duplicate decisions.log records and up to ~192 API
calls. The daily report's junk list shows the same message ~96 times (each with its own APPROVE
number), and the sender-history index counts 96 "junked" for that domain forever — which suppresses
future legitimate SENDER HISTORY lines for the domain (`delivered < junked` gate at 3910) long after
dry-run is off.

**Fix direction:** Keep the "don't cache" retry semantics but add a per-run/persistent dry-run-seen
sidecar (msg_id → verdict) consulted before classification, so a dry-run SPAM is logged once and
skipped (not re-billed) until dry-run turns off; or dedupe by MESSAGE-ID in both report parsing and
the history index.

**Complexity: moderate.**

---

## 13. The filter marks MailWarden's own proposal/analysis emails as READ before the owner sees them

**Files/lines:** `spam_filter.py:6008-6030` (loop-top guard: `mark_uid_seen` + record processed on
any `X-MailWarden-System: 1` mail).

**Root cause:** Every MailWarden system email (FP analyses, acks, notifications) is delivered to
the same polled inbox. The next tick (≤15 min) fetches it UNSEEN and marks it `\Seen`. An owner who
triages by unread count may never notice a proposal — which then expires. Marking seen is not
required for loop prevention (the processed_ids record already prevents reprocessing); it only
saves refetch bandwidth.

**Fix direction:** Record processed but leave the message UNSEEN (mirrors the MWR own-report skip at
7634-7642, which deliberately leaves the report unread "so the owner still reads the report").
Accept the refetch cost, or fix finding 20 to eliminate it.

**Complexity: simple.** (Confirm with Matt — visibility of MailWarden mail is a product call.)

---

## 14. Forwarding (instead of replying to) an FP analysis email is misrouted into the False-Positive teach handler

**Files/lines:** `spam_filter.py:2196-2258` (`detect_email_command`: strips `Fwd:` then
prefix-matches "false positive"), `spam_filter.py:6039` (command detection runs BEFORE the SFID
branch), `spam_filter.py:6197+` (FP handler).

**Root cause / scenario:** Subject `Fwd: False Positive Analysis [SFID-x] — …` (an owner who hits
Forward-to-self with "YES" instead of Reply — a common non-technical slip) strips to
`false positive analysis [sfid-x]…`, matches the `false positive` table entry, and enters the FP
teach handler — which parses MailWarden's own analysis email as a "wrongly junked original",
generates a bogus new analysis + a NEW SFID, and never routes the YES. The real proposal stays
open; the owner now has two confusing threads.

**Fix direction:** In `detect_email_command` (or at the call site), refuse command detection when
the subject carries `[SFID-` / `[MWR-` — those tokens only ever exist on MailWarden conversation
mail.

**Complexity: simple.**

---

## 15. Multi-verb report replies are partially and silently ignored

**Files/lines:** `spam_filter.py:435-447` (`parse_rule_review_command`: "DROP wins if both
appear"), `spam_filter.py:7644-7755` (APPROVE handled → `continue`; any KEEP/DROP in the same reply
never examined), `daily_report.py:1156` + `598-601` (the same report invites APPROVE and KEEP/DROP
in adjacent sections).

**Root cause / scenario:** One report legitimately solicits both verbs. Owner replies
`APPROVE 2` and `DROP 1` in one email: the APPROVE branch runs and continues; DROP 1 is silently
dropped, and the ack (listing only approvals) implies the reply was fully handled. Similarly
`KEEP 1 / DROP 2` executes only the DROP. No error, no note.

**Fix direction:** After handling the first verb, scan the reply for the other verbs and append an
honest line to the ack ("I also saw 'DROP 1' — please send that in its own reply"), or process all
verbs in one pass.

**Complexity: simple.**

---

## 16. "expired" refinement-log events are never written — Dashboard history is blind to expirations

**Files/lines:** `spam_filter.py:2951-2959` (docstring declares `expired` a canonical event),
`daily_report.py:789-815` (`expire_pending_signals` — sets status, never logs the event),
`spam_filter.py:7226-7239` (SFID expiry path — same), `app/mailwarden_app/dashboard.py:2946`
(History tab filters for `{"rejected", "expired", "withdrawn", "deleted"}`).

**Root cause / scenario:** Both expiry paths update pending_signals.json but never
`append_refinement_log({"event": "expired", ...})`. The Dashboard's "Rejected/Expired history"
section therefore never shows an expiration; a proposal that silently expired (e.g. because of
findings 1/9/11/13) leaves no visible trace anywhere except a line in one daily report.

**Fix direction:** Emit the `expired` event in both expiry paths (id + sfid + headline).

**Complexity: simple.**

---

## 17. FP narrowings (the main email teach path) are unscoped, mislabeled in the prompt, invisible/undeletable in the Dashboard, and exempt from item-(b) review

**Files/lines:** `spam_filter.py:3016-3046` (`apply_signal_changes` appends
`"REFINEMENT (from_analysis): …"` to `signals.soft_signals`), `spam_filter.py:3462-3463` (injected
as `LEARNED SOFT SIGNAL:` under the spam-signals section), `spam_filter.py:7479-7480` (ack tells the
owner to reverse it by asking Claude to edit signals.json), `daily_report.py:998-1000` (rule review
captures `R-` ids only — soft-signal narrowings get derived `S-` ids and are filtered out),
`app/mailwarden_app/dashboard.py:3037-3052` (rendered read-only under "Standard rules" with the
caption "These flags themselves aren't AI-learned").

**Root cause:** The legacy FP-approval path predates the ai_refinements machinery and was never
integrated with P1 scoping, F5/item-(b) review, or the Dashboard's refinement management:
- The narrowing is **global** (soft_signals have no scope) even when taught from one inbox.
- It is injected under a header that frames entries as **spam indicators**, although its text is a
  narrowing/exception — the model must infer the inversion from free text.
- If a narrowing itself later causes junking (or fails to), the owner cannot DROP it (S- filter),
  cannot delete it in the GUI (only ai_refinements have Delete), and the GUI actively mislabels it
  as "not AI-learned".

**Concrete failure scenario:** Owner approves an FP narrowing whose PROPOSED CHANGE text is broad.
It applies to every account, appears nowhere manageable, and the only removal instruction shipped
to a non-technical owner is "ask Claude to revert signals.json".

**Fix direction:** Route approved FP narrowings through the ai_refinements store (kind
"fp_narrowing", verdict "legitimate", scoped to the teaching account) so they inherit scope,
Dashboard management, and item-(b) reviewability. Needs Matt's sign-off (changes what a taught
narrowing does across accounts).

**Complexity: moderate** (migration/product decision).

---

## 18. Mid-run staleness after a DROP/APPROVE: retired rules keep classifying/attributing for the rest of the run; APPROVE can re-enqueue a just-retired rule

**Files/lines:** `spam_filter.py:5834-5840` (signals loaded once per run), 5925-5932 (per-account
prompt + `account_injected_ids` built before the message loop), 7739-7745
(`enqueue_rule_reviews(review_pairs, signals, …)` uses the run-start snapshot),
7805-7806 (DROP retires on disk only).

**Root cause / scenario:** A DROP handled early in a run retires the rule on disk, but the
in-memory `signals`, the already-built per-account prompt, and `account_injected_ids` are never
refreshed — messages later in the same run are still classified with (and attributed to) the
retired rule. Conversely an APPROVE later in the same run consults `_active_refinement` against the
stale snapshot and can re-enqueue the just-retired rule into rule_reviews.json (it is hidden from
rendering by `ordered_rule_reviews`' active filter, but the queue entry lingers until the 30-day
prune).

**Fix direction:** After a successful DROP, drop the rule id from the in-memory
snapshot/`account_injected_ids` (or set a flag to rebuild the prompt for subsequent accounts).
Low urgency — the window is one run.

**Complexity: simple.**

---

## 19. `handle_new_pattern` reports success even when the proposal email failed to send

**Files/lines:** `learn_signals.py:1482-1487` (`sent = _send(...)` → logged, but function returns
True regardless), `learn_signals.py:1625-1640` (watermark advances).

**Root cause / scenario:** The proposal is created in pending_signals.json, `_send` fails (SMTP
outage), the learner logs "send FAILED" but returns True; the watermark advances so nothing ever
retries the email. The owner's only remaining surface is the Dashboard pending window and the daily
report — the push channel is silently gone. (Same header omission as finding 1 lives in `_send`.)

**Fix direction:** Minimal: keep the proposal but record a `send_failed` event in the refinement
log so the Dashboard/report can surface it; optionally re-send on the next learner run while the
conversation is still `awaiting_reply` and unreceipted.

**Complexity: simple.**

---

## 20. Every already-processed-but-unread inbox message is fully re-downloaded on every tick

**Files/lines:** `spam_filter.py:5982-6005` (loop: `fetch_raw_email` (full `BODY.PEEK[]`) happens
BEFORE the `msg_id in account_processed` skip).

**Root cause / scenario:** The filter never marks classified ham `\Seen` (correct — the owner must
see it as unread), and processed-skip requires the Message-ID, which is only known after fetching
the full body. So an inbox with N unread messages costs N full-body downloads every tick, forever
(30-day processed retention), plus daily reports' `[MWR]` copies and any own-mail left unseen.
Bandwidth/latency only — no correctness impact — but it grows linearly with unread-inbox size and
can push a tick past the interval on large mailboxes.

**Fix direction:** Fetch headers first (`BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]`), check
processed_ids, then fetch the full body only for new messages; or track per-folder UIDVALIDITY+UID
watermarks.

**Complexity: simple-moderate** (IMAP plumbing; needs care with servers lacking UIDPLUS).

---

## Known gaps / notes (not counted as findings)

- **Dashboard pending window:** false_positive conversations have Withdraw but no Approve button —
  approval is email-only (`dashboard.py:2874-2877`). Matt has already flagged ACCEPT (+ WITHDRAW)
  buttons as future work. Recorded here as the known gap; do not implement without his go-ahead.
- **Enabled-account default mismatch:** `spam_filter.py:5903` treats a missing `enabled` key as
  disabled; `daily_report.py:1404` treats it as enabled. An account entry without the key gets
  daily reports for an inbox that is never filtered. One-line alignment when convenient.
- **Sibling-disease sweep result (rigid regex on LLM output):** post-`29a7c42`, `fp_analysis`
  parsing is tolerant and fails honestly (`_parse_fp_proposed_changes` + `_fp_changes_appliable` +
  `_FP_APPLY_FAILED_BODY`); residual rigidity: the capture still requires the TRADEOFF and
  MY RECOMMENDATION sections to exist in order — a reordered/omitted section parses empty but now
  fails honestly, which is acceptable. Learner and classifier outputs are JSON-parsed with fence
  stripping, brace salvage, and strict validation (`call_claude` W8/W9,
  `_classify_once`/`_validate_classification` F4) — no further rigid label-scrapers found.
  `fp_followup` output is relayed verbatim (no parsing). The remaining scraper risks are findings
  3 (bracket mismatch) and the phrase-matcher brittleness exploited in finding 1.

---

## Summary

**20 findings: 1 complex, 6 moderate, 13 simple.**

- Complex: #2 (pending-merge clobber).
- Moderate: #4 (mark-seen-before-verify), #6 (APPROVE no-op for deterministic blocks),
  #11 (HTML-only/bottom-post replies), #12 (dry-run re-billing + history poisoning),
  #10 (irreversible DROP promise — moderate if the restore path is built), #17 (FP-narrowing
  integration).
- Simple: #1 (top severity — fix first), #3 (plus live verification), #5, #7, #8, #9, #13, #14,
  #15, #16, #18, #19, #20.

Recommended fix order for sessions (hardest-first per instruction, but note #1 and #3 are
tiny-diff/high-impact and should ride along with the first session regardless):
**#2 → #4 → #6 → #11 → #12 → #17 → #10 → then the simple batch (#1, #3, #5, #7, #8, #9, #13-#16,
#18-#20).**

---

## FIX STATUS — updated 2026-07-04

Each landed fix went through the standard gate: plan → master vet → implementation (Opus 4.8)
→ independent review on a different model (Sonnet) → commit on PASS. Every fix kept the offline
eval prompt byte-identical (the classifier prompt is untouched by all of this work).

**DONE — 8 of 20 fixed and pushed** (branch `calibration-security-build1`):

| # | Fix | Commit |
|---|-----|--------|
| 1 | Learner proposal emails self-destructed one tick after sending | `4f3d385` |
| 2 | `persist_pending_merge` reverted concurrent Dashboard/report changes | `b26d40e` |
| 4 | SFID/MWR reply handlers marked mail read before finishing | `922e536` |
| 6 | APPROVE-rescue honest per block source; blacklist no longer double-listed | `7a208fd` |
| 11 | HTML-only replies now read; unreadable replies get an honest ack | `0c37735` |
| 12 | Dry-run spam classified once, not re-billed every tick | `beb546f` |
| 10 | DROP "reversible" promise made real via a `RESTORE n` reply verb | `1feb96d` |
| 17 | Legacy false-positive teachings migrated into the visible/scoped store | `ac52930` |

**REMAINING — 12, triaged 2026-07-04 (all still real), grouped into 6 prompt-neutral batches:**

- **Batch 1 — #7, #15** (reply-command ack honesty): plan vetted + approved, ready to implement.
- **Batch 2 — #14, #5** (FP-forward misroute + swallowed teach-path API failures).
- **Batch 3 — #8** (retired-rule approval falsely acked "now active"). Owner decision: reply
  honestly and point to `RESTORE`, don't silently resurrect a dropped rule.
- **Batch 4 — #3, #18** (dead rule-attribution chain + mid-run staleness after DROP).
- **Batch 5 — #13, #20** (own suggestion mail left unread + stop re-downloading processed mail).
  Owner decision on #13: leave MailWarden's own proposal/analysis mail unread.
- **Batch 6 — #16, #19, #9** (missing "expired" history events + silent proposal-send failure +
  report "reply YES" copy fix). Owner decision on #9: fix the wording to point at the proposal
  email.

After the batches land, a fresh signed installer is needed — the live M1 build currently has
none of these 20 fixes.

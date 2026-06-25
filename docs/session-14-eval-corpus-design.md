# Session 14 — Private Eval Corpus + Scoring Harness (approved design)

Status: design approved by Matt 2026-06-24. Implementation not yet started.
Audit reference: AUDIT-2026-06-11-bug-report.md, Part 3 item 5; Part 4 "Session 14".

## Purpose (and its limits)

A **local, offline measuring tool** whose only job is to be a **regression guardrail**
for the Sessions 15+ spam-filter redesign (signal re-weighting + FP-driven rule
review). It scores the filter against a hand-labeled set of real emails so that a
tuning change can be shown to help — or at least not to quietly break good mail —
instead of being a guess.

It is **not** shipped to end users, **not** a product feature, and it **does not
touch the live filter, teaching, or learner code.** Its value is contingent on
actually doing the Sessions 15+ redesign; absent that work, it has no use.

Honest limitations (to be stated in the harness output, not hidden):
- Small (~79 emails), single-owner, two accounts only — representative of Matt's
  mail, not the world. Catches cliffs, not subtle 1–2% shifts.
- **No legitimate mail carrying a passing authentication verdict.** The nthmonkey
  account stamps no `Authentication-Results`; the AOL account (Matt's dad's) has no
  curated legit/FP mail. So the "auth-pass + brand-match → trust" rescue path is
  covered by review, not by the corpus.
- Spam skews toward obvious/already-provider-caught examples (esp. AOL). Inbox-spam
  (the real catch target) is kept readable separately so easy spam doesn't inflate
  the recall number.

## Inputs — the labeled corpus

Source of truth = three folders on Matt's Desktop under `MailWarden-Benchmark/`
(the folder IS the label):

| Folder | Label | Meaning |
|---|---|---|
| `1-Spam` | spam | should be junked |
| `2-Legitimate-Newsletters-and-Marketing` | legit | should NOT be junked |
| `3-Legitimate-Personal` | legit | should NOT be junked |

`_excluded/` holds items pulled from the corpus (a mislabeled political email; a
forwarded duplicate with broken headers) — ignored by the builder.

Emails were exported via drag-to-Finder (full original headers preserved). No
scrubbing/anonymization in this version — scrubbing was only ever a *shipping*
requirement, and we are not shipping. (Scrubbing returns only if Matt later chooses
to commit a small sample into the repo as a permanent test fixture — a separate,
optional step.)

## Component 1 — corpus builder

Reads the three Desktop folders, parses each `.eml`, attaches the folder's label,
and assembles a labeled set the harness can consume. Skips `_excluded/`,
`.DS_Store`, and non-`.eml` files. Records, per email, enough to read results
later (filename, label, From, subject, receiving account if derivable, and whether
the spam was inbox-delivered vs already provider-junked).

## Component 2 — scoring harness (simple; NOT a tracking tool)

A small script run from the terminal that:
1. Reports the email count and estimated API cost (~$0.0043/email on Haiku;
   ~$0.34 for the current 79) and **waits for explicit confirmation** before
   spending anything.
2. Runs every email through the **real filter at shipped defaults** (default
   `signals.json`, default model) via the existing `classify_eml_offline` entry
   point in `payload/MailWarden/src/spam_filter.py`. Offline except for the
   Claude API call; no IMAP, no folder moves, no writes to decisions.log /
   token_usage.json.
3. Scores each verdict against the folder label and prints plain English:
   recall (share of real spam caught), precision (share of junked that was truly
   spam), false-positive count, and the **list of every misclassified email**.
4. Optionally dumps per-email results to a plain text file so two runs (before vs
   after a redesign) can be laid side by side **by hand**.

Explicitly OUT of scope (vestige of the discarded "watch it improve over time"
goal): dated run-history, auto-compare-to-last-run, any persistent tracking, any
dashboard/product surface.

Usage pattern: run once now to capture a baseline; run again after a Sessions 15+
change to confirm it helped.

## Component 3 — regenerate stale baselines

Regenerate the stale `tests/_out` baselines the audit flagged, since the offline
harness is being built anyway.

## Storage & safety

- Built corpus and run-result files live in a **local, git-ignored** working
  directory on Matt's machine — never committed, never under `payload/`, never in
  the installer. The Desktop folders remain the editable source.
- No changes to live filter / teaching / learner code. Purely additive, offline.
- Do NOT use the superpowers SDD skill or write under `.superpowers/` or
  `docs/superpowers/` (it leaks dev paths into the build's pre-flight audit).

## Workflow note

Per the audit's fix-workflow rule, the implementing session must PLAN first in plan
mode and STOP; the master vets the plan against real code before any code is
written; a separate-model session reviews the diff; the master commits after PASS.

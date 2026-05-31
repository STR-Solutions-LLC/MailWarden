# Forwarded Email Format Research: Multi-Client Parsing for MailWarden
**Date:** 2026-04-19
**Purpose:** Extend `parse_forwarded_email()` coverage from Apple Mail to the top 10 email clients worldwide.

---

## Section 1: Top 10 Email Clients by Market Share (2025-2026)

Source: Litmus Email Analytics, February 2026 (1.1 billion tracked opens).

| Rank | Client | Est. Share | Platform |
|------|--------|-----------|----------|
| 1 | Apple Mail (iPhone + iPad + macOS combined) | ~46% | iOS, iPadOS, macOS |
| 2 | Gmail | ~24% | Web, Android, iOS app |
| 3 | Outlook (desktop) | ~6% | Windows, macOS |
| 4 | Yahoo Mail | ~2% | Web, iOS, Android |
| 5 | Google Android Mail | ~1.3% | Android (AOSP / Google account) |
| 6 | Outlook.com (web) | ~0.4% | Web (also "New Outlook" on Windows) |
| 7 | Thunderbird | ~0.2% | Windows, macOS, Linux |
| 8 | Samsung Mail | ~0.02% | Android (Samsung devices) |
| 9 | Spark (Readdle) | < 0.1% (est.) | macOS, iOS, Android, Windows |
| 10 | Airmail | < 0.1% (est.) | macOS, iOS |

**Notes on selection:**

- Litmus market share data tracks email opens, not installs, and Apple's Mail Privacy Protection inflates Apple figures. True Apple share may be slightly lower; Gmail true share slightly higher.
- Google Android Mail (#5) and Gmail (#2) both use the same "On ... wrote:" inline attribution — they parse identically.
- Samsung Mail (#8) uses the same "On ... wrote:" block as stock Android Mail.
- Spark (#9) and Airmail (#10) are included because MailWarden targets Mac users — both are popular third-party Mac/iOS clients that represent the "power user" segment most likely to use MailWarden.
- Superhuman, Fastmail, ProtonMail, and iCloud Mail were considered but have Litmus share below 0.02% individually; their formats fall into existing pattern families (inline "On ... wrote:" or RFC-2822-style header block) and are covered by the unified patterns in Section 3.
- AOL Mail was excluded; its format is functionally identical to Yahoo Mail.

---

## Section 2: Forward Format Per Client

### 1. Apple Mail (macOS)

**Standalone forward ("Begin forwarded message:" block):**
```
Begin forwarded message:

From: Display Name <addr@domain.com>
Subject: Original Subject
Date: 19 April 2026 at 10:23:45 AM PDT
To: recipient@domain.com
```
- The divider line is exactly `Begin forwarded message:` on its own line, no dashes.
- Headers follow in US-English locales. Header order: From, Subject, Date, To (may vary).
- Date format is verbose: `19 April 2026 at 10:23:45 AM PDT` — note the "at" separator.
- Display name is present when in Contacts; absent when not (bare address only).
- Angle brackets around the address are standard but can be absent in some locales.

**Inline forward (when user is in a reply thread and re-forwards):**
Same "Begin forwarded message:" block is inserted — Apple Mail does not use "On ... wrote:" for standalone forwards. It uses the block form exclusively for Forward actions.

**EXISTING SUPPORT:** Fully handled by the `apple-mail` divider branch.

---

### 2. Gmail (Web + Mobile App)

**Standalone forward (most common — "Forwarded message" block):**
```
---------- Forwarded message ---------
From: Display Name <addr@domain.com>
Date: Mon, Apr 19, 2026 at 10:23 AM
Subject: Original Subject
To: recipient@domain.com
```
- Divider is exactly: 10 dashes, space, "Forwarded message", space, 9 dashes.
- Full string: `---------- Forwarded message ---------`
- Asymmetric dash counts (10 left, 9 right) — this is deliberate and consistent.
- Date format: abbreviated weekday + abbreviated month, no ordinal: `Mon, Apr 19, 2026 at 10:23 AM`
- No timezone suffix in the plain-text Date line.
- Locale variations exist (non-English Gmail may use the local language for "Forwarded message").

**Inline reply quote (when replying to a forwarded thread):**
```
On Mon, Apr 19, 2026 at 10:23 AM, Display Name <addr@domain.com> wrote:
```
- "On" prefix, comma-separated date/time, then sender with display name and angle-bracketed address.
- Quoted lines below are prefixed with `>`.

**EXISTING SUPPORT:** The `dashes+forward` regex catches the Gmail block (`-{3,}.*[Ff]orward.*-{3,}`). The inline form is caught by the `inline-quote-on-wrote` pattern. **Gap:** the exact 10/9 dash asymmetry is matched by the current regex but worth verifying in tests.

---

### 3. Outlook Desktop (Classic, Windows/macOS — Office 2016+)

**Standalone forward:**
```
-----Original Message-----
From: Display Name <addr@domain.com>
Sent: Monday, April 19, 2026 10:23 AM
To: recipient@domain.com
Subject: Original Subject
```
- Divider: exactly `-----Original Message-----` (5 dashes each side).
- Uses `Sent:` instead of `Date:` — important distinction from RFC-2822 style.
- Display name and email address present when sender is in Contacts; may show only display name in New Outlook (see below).
- No timezone in `Sent:` line.
- Header order: From, Sent, To, Subject (Cc may follow).

**EXISTING SUPPORT:** Caught by the `outlook` regex `^-{3,}\s*[Oo]riginal\s+[Mm]essage\s*-{3,}\s*$`. The `Sent:` header is NOT currently extracted — the code looks for `date:` only. **Gap:** if the engineer wants `original_date`, a `sent:` fallback is needed.

---

### 4. New Outlook (Windows desktop "New Outlook" + Outlook.com web, 2024-2026)

**Critical change confirmed (April 2025 Microsoft Q&A):** New Outlook's forward/reply header block now shows **only display names, not email addresses**. The plain-text block looks like:
```
From: Display Name
Sent: Wednesday, April 19, 2026 10:23 AM
To: Recipient Name
Subject: Original Subject
```
- No angle-bracketed email address in the `From:` line.
- This is an unannounced change, possibly unintentional, with no user toggle.
- Classic Outlook still shows the address: `From: Display Name <addr@domain.com>`.
- The same `-----Original Message-----` divider is still used in plain-text mode.
- In HTML mode (default), the separator is a rendered horizontal rule — irrelevant to plain-text parsing, but note that the plain-text part may be absent if the sender composed in HTML only.

**UNVERIFIED:** Whether this "no address" behavior is now permanent or will be reverted. Field test with a real New Outlook account is strongly recommended.

**Gap for MailWarden:** If `From:` has no angle-bracketed address, all current extraction patterns fail to return an email address. A fallback pattern to extract a display-name-only `From:` line, then look for an address in the full original `From:` envelope header, may be needed.

---

### 5. Yahoo Mail (Web + Mobile)

**Standalone forward:**
```
----- Forwarded Message -----
From: "Display Name" <addr@domain.com>
To: recipient@domain.com
Sent: Monday, April 19, 2026, 10:23 AM EDT
Subject: Original Subject
```
- Divider: 5 dashes, space, "Forwarded Message", space, 5 dashes (symmetric, title-cased).
- Display name is often quoted: `"Display Name"`.
- `Sent:` used instead of `Date:`, includes timezone abbreviation.
- Header order: From, To, Sent, Subject.

**EXISTING SUPPORT:** Caught by the `dashes+forward` regex. The quoted display name (`"Display Name"`) is handled by the `.strip('"')` call in the inline branch but NOT in the block branch — the code currently does `from_match.group(1).strip()` without stripping quotes. **Gap:** block-mode From values with surrounding quotes will include the quotes in `original_from`.

---

### 6. Google Android / AOSP Mail

Uses identical inline attribution as Gmail web:
```
On Mon, Apr 19, 2026 at 10:23 AM, Display Name <addr@domain.com> wrote:
```
Quoted lines prefixed with `>`. No separate block-style forward header. Handled by existing `inline-quote-on-wrote` pattern.

---

### 7. Outlook.com Web (Distinct from New Outlook Desktop)

When composing in plain text, Outlook.com uses the same `-----Original Message-----` block as Classic Outlook, including `Sent:` and (currently) the full `From:` line with address. Subject to the same New Outlook display-name-only change described in #4 above, since the web app is the same codebase.

**UNVERIFIED:** Whether Outlook.com web has already rolled out the display-name-only change seen in the desktop New Outlook.

---

### 8. Thunderbird

**Standalone forward:**
```
-------- Forwarded Message --------
Subject: Original Subject
Date: Mon, 19 Apr 2026 10:23:45 -0700
From: Display Name <addr@domain.com>
To: recipient@domain.com
```
- Divider: 8 dashes, space, "Forwarded Message", space, 8 dashes (symmetric, title-cased).
- Header order: Subject, Date, From, To — note Subject comes FIRST, before From.
- Date in RFC-2822 format with numeric timezone offset: `-0700`.
- Full address in angle brackets is standard.
- Optionally, "-------- Original Message --------" is used by some Thunderbird configurations.

**EXISTING SUPPORT:** Caught by `dashes+forward` regex (matches "Forwarded Message"). The Subject-first ordering is unusual but doesn't affect From extraction since the code uses `re.search` not sequential parsing. **Confirmed working for From.**

---

### 9. Samsung Mail (Android)

Samsung Mail's forward format on Android is identical to the generic Android/Gmail inline form:
```
On Mon, Apr 19, 2026 at 10:23 AM, Display Name <addr@domain.com> wrote:
```
Handled by existing `inline-quote-on-wrote` pattern. Some Samsung versions may omit the display name (bare address only); handled by the `bare_inline_match` fallback.

---

### 10. Spark (macOS / iOS)

Spark uses the same "On ... wrote:" inline attribution as iOS Mail and Gmail. In HTML mode (default), it renders a styled header block, but the plain-text multipart part uses:
```
On Mon, Apr 19, 2026 at 10:23 AM, Display Name <addr@domain.com> wrote:
```
**UNVERIFIED:** Whether Spark's plain-text part ever uses a dashed block header instead. No public documentation found. Recommendation: collect one real Spark .eml forward and inspect the text/plain part.

---

### Bonus: Airmail (macOS / iOS)

Airmail defaults to HTML composition. Its text/plain multipart part typically uses:
```
On Mon, Apr 19, 2026 at 10:23 AM, Display Name <addr@domain.com> wrote:
```
**UNVERIFIED:** Same caveat as Spark. Airmail has customizable reply/forward templates, so the attribution line could be user-modified.

---

### Bonus: iOS Mail (iPhone / iPad)

iOS Mail uses an inline "On ... wrote:" attribution for both replies and forwards:
```
On Mon, Apr 19, 2026 at 10:23 AM, Display Name <addr@domain.com> wrote:
```
- Date format matches macOS Mail inline style.
- When the sender has no display name configured, falls back to bare address.
- Quoted lines below prefixed with `>`.
- **Important:** iOS Mail also produces "Begin forwarded message:" block format when the forward is initiated fresh (not from within a reply thread) — same as macOS Apple Mail.

---

## Section 3: Unified Parsing Strategy

### Design Principles
1. Try the most specific, highest-fidelity patterns first (block headers with explicit dividers).
2. Fall through to inline "On ... wrote:" patterns.
3. Never return a display name from a block-header `From:` line without also stripping surrounding quotes.
4. Flag New Outlook display-name-only `From:` lines as a known degraded case.

### Pattern Order (most specific to least specific)

---

#### Pattern A — Apple Mail Block (highest specificity)
```python
# Anchor: literal "Begin forwarded message:" on its own line
# Then scan below for a "From:" line
r'Begin forwarded message:'
# After matching this divider, extract:
r'(?im)^\s*From:\s*(?:"?([^"<\n]+)"?\s*)?(?:<([^>\s]+@[^>\s]+)>)?'
```
- Covers: Apple Mail macOS, iOS Mail (standalone forward)
- Edge cases: Display name absent (bare address only); angle brackets absent in rare locales
- Confidence: HIGH

---

#### Pattern B — Gmail "Forwarded message" Block
```python
# Anchor: the asymmetric dashed divider Gmail uses
r'^-{8,12}\s+Forwarded message\s+-{7,11}\s*$'
# Then extract From: line below it
r'(?im)^\s*From:\s*(?:"?([^"<\n]+)"?\s*)?(?:<([^>\s]+@[^>\s]+)>)?'
```
- Covers: Gmail web, Gmail mobile (both iOS and Android)
- Edge cases: Non-English Gmail locales use translated "Forwarded message" — the parent `dashes+forward` regex handles this with `[Ff]orward` but non-English locales are not covered
- Confidence: HIGH for English; UNVERIFIED for non-English

---

#### Pattern C — Outlook / Yahoo / Thunderbird Dashed Block (generic)
```python
# Covers: "-----Original Message-----", "----- Forwarded Message -----",
#         "-------- Forwarded Message --------", and variants
r'^-{3,}\s*(?:Original Message|Forwarded Message|Begin Forwarded Message)\s*-{3,}\s*$'
# Then extract From: and Sent:/Date: below
r'(?im)^\s*From:\s*(?:"?([^"<\n]+)"?\s*)?(?:<([^>\s]+@[^>\s]+)>)?'
r'(?im)^\s*(?:Sent|Date):\s*(.+)$'   # handles both Date: and Sent: keywords
```
- Covers: Classic Outlook, New Outlook (plain text), Outlook.com, Yahoo Mail, Thunderbird, eM Client, and any client using an RFC-style forward block
- Edge cases:
  - Yahoo wraps display name in quotes: `"Display Name"` — strip with `strip('"')` after extraction
  - Thunderbird puts Subject before From — use `re.search`, not sequential parsing
  - New Outlook may omit the email address entirely (display name only in From:) — see Pattern F
- Confidence: HIGH for address extraction when address is present; MEDIUM for New Outlook

---

#### Pattern D — Bare-dash + From: Next Line
```python
# Covers: some older clients that insert "---" then a From: line immediately after
r'^-{3,}\s*$'   # match line of dashes...
# ...only if next non-empty line starts with "From:"
```
- Covers: Occasional Outlook misconfiguration, older webmail
- Confidence: MEDIUM (already implemented as `dashes+from-next`)

---

#### Pattern E — Inline "On DATE, NAME <addr> wrote:" (primary inline)
```python
# Primary: display name + angle-bracketed address
r'On\s+[^\n]{3,120}?,\s*(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:'
```
- Covers: Gmail inline, iOS Mail, Android Mail, Samsung Mail, Spark, Airmail, Superhuman, Fastmail, ProtonMail, Yahoo inline, and virtually every modern webmail client
- Edge cases:
  - Date line may wrap — the `[^\n]{3,120}?` restriction prevents runaway matching but also prevents matching wrapped dates. Use `re.DOTALL` version with tighter bounds as a secondary attempt if no match.
  - Display name may contain a comma (e.g., "Smith, John") — the greedy `.+?` before `<` will capture it correctly since it stops at the last `<`
- Confidence: HIGH

---

#### Pattern F — Inline "On DATE, bare@address.com wrote:" (no display name)
```python
# Fallback: no display name, bare address, no angle brackets
r'On\s+[^\n]{3,120}?,\s*([^<>\s]+@[^<>\s]+)\s+wrote:'
```
- Covers: Senders with no configured display name, some Android clients
- Confidence: HIGH (already implemented)

---

#### Pattern G — New Outlook Display-Name-Only From: Line (degraded case)
```python
# After matching a dashed block divider, if From: contains no angle-bracketed address:
r'(?im)^\s*From:\s*([^<\n]+)\s*$'
```
- Returns `(display_name, None)` — email address will be None
- Covers: New Outlook 2025 forward headers where address is stripped
- The caller should surface a user-facing message: "MailWarden found the sender name but not their email address. Try forwarding from Classic Outlook."
- Confidence: MEDIUM (behavior may be reverted by Microsoft)

---

#### Pattern H — Short inline "Name <addr> wrote:" (no "On" prefix)
```python
# Last resort: no date prefix at all
r'^(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:\s*$'
```
- Covers: Some mobile clients that strip the date, older Blackberry clients
- Edge cases: Can match unrelated body text — guard with: name must be <= 80 chars and contain no newline
- Confidence: LOW — use only after all other patterns fail

---

### Summary: Proposed Function Skeleton

```python
def extract_original_sender(body: str) -> tuple:
    """
    Returns (display_name, email_address) or (None, None).
    display_name may be None even when email_address is present (bare address).
    email_address may be None in New Outlook display-name-only degraded case.
    """
    # 1. Detect block-style divider and extract From: line
    #    Try Pattern A (Apple Mail) -> Pattern B (Gmail) -> Pattern C (generic dashed)
    #    -> Pattern D (bare dash + From: next line)
    # 2. If block found, parse From: with quote-stripping
    #    -> Pattern G if no address found in From: line
    # 3. If no block, try inline patterns:
    #    -> Pattern E (with display name)
    #    -> Pattern F (bare address)
    #    -> Pattern H (no "On" prefix, last resort)
    # 4. Return (None, None) if nothing matched
    pass
```

---

## Section 4: Recommended Test Fixtures

Each snippet is just the attribution block / forward header — not a full body. These represent the minimum the unit test suite should cover.

---

**Fixture 1 — Apple Mail macOS (block, with display name)**
```
Begin forwarded message:

From: Jane Doe <jane@example.com>
Subject: Your order has shipped
Date: 19 April 2026 at 10:23:45 AM PDT
To: recipient@example.com
```
Expected: `("Jane Doe", "jane@example.com")`

---

**Fixture 2 — Apple Mail / iOS Mail (block, bare address — no display name in Contacts)**
```
Begin forwarded message:

From: noreply@bulkmailer.com
Subject: Exclusive offer inside
Date: 19 April 2026 at 10:23:45 AM PDT
To: recipient@example.com
```
Expected: `(None, "noreply@bulkmailer.com")`

---

**Fixture 3 — Gmail web (Forwarded message block)**
```
---------- Forwarded message ---------
From: Spammer Joe <joe@spammy.biz>
Date: Mon, Apr 19, 2026 at 10:23 AM
Subject: Act now — limited time
To: recipient@example.com
```
Expected: `("Spammer Joe", "joe@spammy.biz")`

---

**Fixture 4 — Classic Outlook desktop (Original Message block)**
```
-----Original Message-----
From: Bob Smith <bob@contoso.com>
Sent: Monday, April 19, 2026 10:23 AM
To: recipient@example.com
Subject: Q2 Budget
```
Expected: `("Bob Smith", "bob@contoso.com")`

---

**Fixture 5 — Yahoo Mail (Forwarded Message block, quoted display name)**
```
----- Forwarded Message -----
From: "Marketing Team" <offers@retailer.com>
To: recipient@example.com
Sent: Monday, April 19, 2026, 10:23 AM EDT
Subject: Weekend sale
```
Expected: `("Marketing Team", "offers@retailer.com")`

---

**Fixture 6 — Thunderbird (Forwarded Message block, Subject-first ordering)**
```
-------- Forwarded Message --------
Subject: Invoice #12345
Date: Mon, 19 Apr 2026 10:23:45 -0700
From: billing@vendor.com
To: recipient@example.com
```
Expected: `(None, "billing@vendor.com")`  (no display name — bare address in From:)

---

**Fixture 7 — Gmail / Android / iOS inline (with display name, "On ... wrote:")**
```
On Mon, Apr 19, 2026 at 10:23 AM, Jane Doe <jane@spammer.net> wrote:

> This is the spam body content.
```
Expected: `("Jane Doe", "jane@spammer.net")`

---

**Fixture 8 — Inline bare address (no display name, "On ... wrote:")**
```
On Mon, Apr 19, 2026 at 10:23 AM, noreply@automated.io wrote:

> Your subscription has been updated.
```
Expected: `(None, "noreply@automated.io")`

---

**Fixture 9 — UNVERIFIED: New Outlook display-name-only (degraded case)**
```
-----Original Message-----
From: Robert Smith
Sent: Wednesday, April 19, 2026 10:23 AM
To: recipient@example.com
Subject: Follow up
```
Expected: `("Robert Smith", None)` — or treat as parsing failure depending on product decision

---

**Fixture 10 — Wrapped date line (long date wraps to next line)**
```
On Monday, April 19, 2026 at
10:23:45 AM Pacific Daylight Time, Jane Doe <jane@example.com> wrote:
```
Expected: `("Jane Doe", "jane@example.com")` — UNVERIFIED, current pattern `[^\n]{3,120}?` will NOT match this; a multi-line variant is needed.

---

**Fixture 11 — Short inline, no "On" prefix (last resort pattern H)**
```
Jane Doe <jane@example.com> wrote:
```
Expected: `("Jane Doe", "jane@example.com")`

---

**Fixture 12 — Mixed-case divider (case-insensitive matching)**
```
----- forwarded message -----
From: spammer@dodgy.ru <spammer@dodgy.ru>
Date: Mon, 19 Apr 2026 10:23:45 +0000
Subject: You won
```
Expected: `("spammer@dodgy.ru", "spammer@dodgy.ru")` — display name equals address when client repeats it; strip to just address.

---

## Gaps and Open Questions

1. **New Outlook display-name-only From: line** — confirmed in April 2025 Microsoft Q&A but unverified as permanent. MailWarden should handle this gracefully (return display name only with a helpful error message rather than failing silently).

2. **Wrapped date lines** — some Apple Mail locales and older iOS versions produce an attribution line where the date portion wraps to a second line before the sender name. The current `[^\n]{3,120}?` constraint blocks this. A two-step approach (detect "On " + scan forward up to 250 chars for an email address) would resolve this.

3. **Quoted display names in block-mode From: lines** — the block parsing branch does not currently strip surrounding `"` characters. Yahoo Mail commonly uses `"Display Name"` format. This is a one-line fix.

4. **Non-English client locales** — Gmail, Outlook, and Yahoo will insert translated divider strings in non-English accounts. If MailWarden users are expected to be English-speaking only, this is low priority. If internationalization is a future goal, the divider regex should be extended.

5. **Spark and Airmail forward format** — no verified plain-text samples found. Recommend: open a Spark/Airmail account, forward one email to a test address, retrieve the .eml, and inspect the text/plain part before implementing these patterns.

6. **`Sent:` vs `Date:` in block headers** — Outlook and Yahoo use `Sent:`, Apple Mail and Thunderbird use `Date:`. The current code extracts `date:` only. If the engineer needs `original_date` from Outlook forwards, a `(?:sent|date):` alternation is required.

---

*Report compiled: 2026-04-19. Sources: Litmus Email Analytics (Feb 2026), Microsoft Q&A (Apr 2025), Mozilla Thunderbird support forums, Gmail format specification (widely reproduced). Items marked UNVERIFIED require test fixture validation.*

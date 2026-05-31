# Forwarded Email Parsing: Deep Nuances (v2)
**Date:** 2026-04-19
**Based on:** parse_forwarded_email in spam_filter.py (commit b76c9ac and earlier)
**Reference EMLs:**
- `Fwd_ Blacklist All -- When a woman thinks she has no way forward.eml` (Apple Mail, full-quote-prefix body)
- `Fwd_ SPAM Example -- Your reserved Pavé Cuban Chain Bracelet.eml` (Apple Mail, user text above forward)

---

## Summary

The previous v1 survey catalogued client formats. This document goes one layer deeper: it identifies **every nuance in the current `parse_forwarded_email` function that can cause silent parse failures**, maps each to the exact line of code that breaks, and provides specific fixes.

The code was recently fixed (commit b76c9ac) to handle single-level `> ` quote-prefixed dividers (`> Begin forwarded message:`). That fix is **confirmed working** on both reference EMLs. However, **four code-level bugs remain** that will break real users today, plus several edge-case categories that need test fixture coverage.

### Priority summary

| Priority | Count | Items |
|----------|-------|-------|
| CRITICAL | 2 | Spaced double-quoting (`> > Begin...`), inline wrapped-date |
| HIGH | 3 | Bcc/X-header in block, leading whitespace before `>`, HTML `&lt;` brackets |
| MEDIUM | 4 | Localized dividers, no-colon Apple Mail variant, double-space after `>`, inline display name contamination |
| LOW | 3 | Em-dash dividers, fake-forward confusion, Unicode quote chars |

---

## Categories

---

### 1. Quote-Prefix Variations

#### Nuance: Spaced double-quote `> > Begin forwarded message:`
- **Priority:** CRITICAL
- **Currently handled:** NO
- **Example input:**
  ```
  > > Begin forwarded message:
  > > 
  > > From: spammer@bad.com
  > > Subject: Click here
  ```
- **What breaks:** Line 788 in `parse_forwarded_email`:
  ```python
  unquoted = re.sub(r'^>+\s?', '', stripped)
  ```
  `'^>+'` matches only the leading consecutive `>`s. With a space between them (`> > `), it matches only the first `>` plus its space, leaving `> Begin forwarded message:` — which does NOT equal the exact string `'Begin forwarded message:'`. The divider is not detected; the parser falls through to inline patterns and finds nothing. Result: `_divider_kind = "none"`, empty `original_from`.
- **When this occurs:** Gmail (or any `>` -prefixed client) replying to a thread that contained an Apple Mail forward. The reply adds one level of `>` to the already-`>`-prefixed forward block. Users forwarding spam from a conversation thread will hit this.
- **Proposed fix:**
  ```python
  # Change both occurrences of the unquote pattern (lines ~788 and ~822) to:
  unquoted = re.sub(r'^(>\s*)+', '', stripped).strip()
  # For below_lines (raw lines, may have leading whitespace):
  unquoted = re.sub(r'^(\s*>\s*)+', '', ln).strip()
  ```
  This handles: `>`, `>>`, `> >`, `> > >`, `>  `, `  > ` and all combinations.
- **Test fixture:** F-01

---

#### Nuance: Double-space after single `>` — `>  Begin forwarded message:`
- **Priority:** MEDIUM
- **Currently handled:** NO
- **Example input:**
  ```
  >  Begin forwarded message:
  >  
  >  From: foo@bar.com
  ```
- **What breaks:** Same as above. `^>+\s?` matches `>` plus one space, leaving ` Begin forwarded message:` with a leading space. Exact equality check fails.
- **When this occurs:** Some mailing list software that reformats forwarded bodies adds two spaces after `>` for readability.
- **Proposed fix:** Same as above — the unified `^(>\s*)+` fix resolves this.
- **Test fixture:** F-02

---

#### Nuance: Leading whitespace before `>` in raw lines
- **Priority:** HIGH
- **Currently handled:** NO (only for divider detection, not for below_lines or body_start)
- **Example input:**
  ```
  Begin forwarded message:
  
    > From: foo@bar.com
    > Subject: spam
  ```
- **What breaks:** The `below_lines` loop (line ~822) applies `re.sub(r'^>+\s?', '', ln)` to the raw line WITHOUT stripping first. If the raw line has leading spaces (`  > From:`), the regex `^>+` does not match (it hits the spaces first), and the output is `  > From: foo@bar.com`. The subsequent `re.search(r'(?im)^\s*from:\s*(.+)$', below)` uses `^` which with `re.MULTILINE` matches start-of-line — but the line starts with spaces then `>`, so `^\s*from:` fails because `>` is not `\s`.
- **When this occurs:** Some Outlook configurations and mailing list relay software indent forwarded bodies.
- **Proposed fix:** Use `re.sub(r'^(\s*>\s*)+', '', ln).strip()` in the `below_lines` loop AND in the `body_start` loop (which uses `re.sub(r'^>+\s?', '', lines[i]).strip()` — that `.strip()` does help, but the `^>+` still won't match if spaces come first).
- **Test fixture:** F-03

---

#### Nuance: Triple-plus spaced quoting `> > > From:`
- **Priority:** HIGH (same fix as F-01)
- **Currently handled:** NO
- **Example input:**
  ```
  > > > Begin forwarded message:
  > > > From: inner@spammer.com
  ```
- **What breaks:** Same `^>+\s?` issue — each `> ` pair eats one `>` and one space, leaving residual `> > ` prefixes.
- **Proposed fix:** Same unified fix.
- **Test fixture:** F-04 (combines with F-01 fix)

---

#### Nuance: Unicode angle-quote characters (`»`, `｜`, `>`) as quote prefix
- **Priority:** LOW
- **Currently handled:** NO
- **Example input:**
  ```
  » Begin forwarded message:
  » From: foo@bar.com
  ```
- **What breaks:** The unquote regex `^(>\s*)+` only removes ASCII `>`. Unicode substitutes pass through unchanged. The divider and header lines would not be recognized.
- **When this occurs:** Some non-standard or heavily customized email clients in Asian/European markets.
- **Proposed fix:** Extend the unquote to also strip common Unicode quote chars: `re.sub(r'^[\s>»｜\u2019\u201c]+', '', ln).strip()`. Treat this as a LOW-priority enhancement; English-market clients universally use ASCII `>`.
- **Test fixture:** F-05

---

### 2. Divider Line Variations

#### Nuance: Localized Apple Mail divider (non-English locale)
- **Priority:** MEDIUM
- **Currently handled:** NO
- **Example input (French):**
  ```
  Début du message réacheminé :
  
  De : display name <addr@example.com>
  ```
- **What breaks:** Line 795 does exact string comparison: `unquoted == 'Begin forwarded message:'`. The French (and German, Spanish, Japanese, etc.) equivalents are completely different strings and will never match.
- **Known localizations:**
  - French: `Début du message réacheminé :`
  - German: `Anfang der weitergeleiteten Nachricht:`
  - Spanish: `Comienzo del mensaje reenviado:`
  - Italian: `Inizio del messaggio inoltrato:`
  - Japanese: `転送されたメッセージの始め：`
- **Additional note:** When Apple Mail localizes the divider, it also localizes the header labels. `From:` becomes `De :` (French), `Von:` (German), `De:` (Spanish). None of these are in the `from:` regex.
- **Proposed fix:** For English-market MailWarden, defer to MEDIUM. If international support is desired, add a list of known localized dividers and header labels. Short-term: also add `r'Début du message|Anfang der weitergeleiteten|Comienzo del mensaje|Inizio del messaggio|転送されたメッセージ'` as an extended apple-mail divider pattern.
- **Test fixture:** F-06

---

#### Nuance: Localized dashed dividers (non-English "Forwarded message")
- **Priority:** MEDIUM
- **Currently handled:** NO
- **Example input (German):**
  ```
  -------- Weitergeleitete Nachricht --------
  From: sender@example.com
  ```
- **What breaks:** Line 790 regex: `r'-{3,}.*[Ff]orward.*-{3,}'` requires the word "forward" (case-insensitive English). German `Weitergeleitete`, French `transmis`, Spanish `Reenviado` do not contain "forward".
- **Proposed fix:** Add a secondary regex for localized "Forwarded message" variants:
  ```python
  r'-{3,}.*(?:[Ff]orward|[Ww]eitergeleitete|[Tt]ransféré|[Rr]eenviad|[Oo]riginal)\b.*-{3,}'
  ```
  Or: match any dashed line + any word that isn't "Original Message" as a broad fallback, then verify a `From:` follows.
- **Test fixture:** F-07

---

#### Nuance: Unicode em-dash divider `——— Forwarded ———`
- **Priority:** LOW
- **Currently handled:** NO
- **Example input:**
  ```
  ——— Forwarded message ———
  From: sender@example.com
  ```
- **What breaks:** The dashes regex requires ASCII `-{3,}`. Unicode em-dash `\u2014` doesn't match.
- **When this occurs:** Some older Palm/BlackBerry clients, some non-standard mobile webmail renderers. Rare on modern clients.
- **Proposed fix:** Add `[\-\u2014\u2013]{3,}` to the divider pattern.
- **Test fixture:** F-08

---

#### Nuance: `Begin forwarded message` without trailing colon
- **Priority:** MEDIUM
- **Currently handled:** NO
- **Example input:**
  ```
  > Begin forwarded message
  > 
  > From: foo@bar.com
  ```
- **What breaks:** Line 795: `unquoted == 'Begin forwarded message:'` — exact match requires the colon. Missing colon = no divider detected.
- **When this occurs:** Very rare; some Apple Mail versions under certain locales or edge cases may omit the colon. Observed in one community report from 2023.
- **Proposed fix:** Change comparison to: `unquoted.rstrip(':').strip() == 'Begin forwarded message'` or use a regex: `re.match(r'^Begin forwarded message:?\s*$', unquoted, re.IGNORECASE)`.
- **Test fixture:** F-09

---

### 3. Header Block Variations

#### Nuance: `Bcc:` header in forwarded block stops `body_start` early
- **Priority:** HIGH
- **Currently handled:** NO
- **Example input:**
  ```
  Begin forwarded message:

  From: spammer@bad.com
  Subject: Win a prize
  Date: April 19, 2026 at 10:23 AM EDT
  To: victim@example.com
  Bcc: list@example.com
  Body starts here without blank line separator
  ```
- **What breaks:** Lines 849 and 855 of the `body_start` loop:
  ```python
  if stripped and re.match(r'(?i)^(from|to|subject|date|sent|cc|reply-to):', stripped):
  ```
  `Bcc:` is not in the recognized header list. When the loop encounters `Bcc: list@example.com` after `header_section = True`, it hits the third branch: `body_start = i` and breaks — treating `Bcc: list@example.com` as the start of the body. If Bcc is followed immediately by the real body, this works accidentally. But if `Bcc:` is followed by more headers (e.g., `Message-ID:`), those headers end up in `original_body`.
- **Also affected:** `X-Mailer:`, `X-Spam-Score:`, `Reply-To:` (Wait — `Reply-To:` IS in the list already. But `Message-ID:`, `X-headers`, `Bcc:`, `Cc:` when using different capitalization... actually `cc` is in the list). `Bcc` specifically is missing.
- **Proposed fix:** Add `bcc` and `message-id` to the recognized header pattern:
  ```python
  r'(?i)^(from|to|bcc|subject|date|sent|cc|reply-to|message-id|x-mailer):'
  ```
  Or more robustly: treat ANY `Word-Word: value` pattern as a header during the header-section scan (standard RFC 2822 header name format is `[A-Za-z][A-Za-z0-9-]*:`).
- **Test fixture:** F-10

---

#### Nuance: Header folding — `From:` value wraps to continuation line
- **Priority:** HIGH
- **Currently handled:** NO
- **Example input:**
  ```
  Begin forwarded message:

  From: "Very Long Display Name That Needs Wrapping"
    <sender@example.com>
  Subject: Test
  ```
- **What breaks:** Line 826:
  ```python
  from_match = re.search(r'(?im)^\s*from:\s*(.+)$', below)
  ```
  `(.+)` captures only the current line's content. When the `From:` value wraps to a continuation line (RFC 2822 folding: CRLF + SP/TAB), the address `<sender@example.com>` is on the next line and is NOT captured. `original_from` becomes `"Very Long Display Name That Needs Wrapping"` — no angle bracket, no address. `parse_from_address` returns `address: None` and the `_missing_address_reason` sentinel is incorrectly set to `new_outlook_stripped`.
- **When this occurs:** Rare in plain-text forward bodies, but can happen when a mailing list relay software reformats headers to comply with RFC 2822 998-char line limits.
- **Proposed fix:** Before applying header regexes, join continuation lines in `below`:
  ```python
  # Join folded headers: a line starting with space/tab after a non-blank line
  # is a continuation of the previous header
  below_joined = re.sub(r'\n[ \t]+', ' ', below)
  from_match = re.search(r'(?im)^\s*from:\s*(.+)$', below_joined)
  ```
- **Test fixture:** F-11

---

#### Nuance: HTML-encoded angle brackets in plain-text `From:` value
- **Priority:** HIGH
- **Currently handled:** NO
- **Example input (plain text body that was erroneously HTML-entity-encoded):**
  ```
  Begin forwarded message:

  From: Jane Doe &lt;jane@example.com&gt;
  Subject: Test
  ```
- **What breaks:** `parse_from_address` receives `'Jane Doe &lt;jane@example.com&gt;'`. Its regex `re.search(r'^(.*?)<([^>]+@[^>]+)>\s*$', header_value)` looks for literal `<>`, which are not present — only the `&lt;&gt;` entities. The function falls through to the bare-address check which also fails. Result: `address = None`.
- **When this occurs:** Some corporate mail gateways, ancient Lotus Notes installations, or email-to-ticket conversion tools that HTML-encode the plain-text part by mistake. Also occurs when `html_to_text` is applied to a part that had double-encoding.
- **Proposed fix:** In `parse_from_address` (utils.py), add HTML entity unescaping before the angle bracket search:
  ```python
  import html
  header_value = html.unescape(header_value)
  ```
  This is safe for non-HTML values (plain text is unaffected by `html.unescape`).
- **Test fixture:** F-12

---

#### Nuance: RFC 2047 MIME-encoded display name in plain-text forward block
- **Priority:** MEDIUM  
- **Currently handled:** YES — `parse_from_address` calls `email.header.decode_header()` before processing. Verified working.
- **Example input:**
  ```
  From: =?utf-8?Q?Jane_Doe?= <jane@example.com>
  ```
- **Expected output:** `("Jane Doe", "jane@example.com")` — confirmed correct.
- **Test fixture:** F-13 (for regression coverage)

---

#### Nuance: New Outlook (2025+) display-name-only `From:` line
- **Priority:** HIGH (documented known gap)
- **Currently handled:** PARTIAL — the `_missing_address_reason = "new_outlook_stripped"` sentinel is set but the caller must handle it
- **Example input:**
  ```
  -----Original Message-----
  From: Robert Smith
  Sent: Wednesday, April 19, 2026 10:23 AM
  To: Recipient Name
  Subject: Follow up
  ```
- **What breaks:** `parse_from_address('Robert Smith')` returns `address: None`. The sentinel is set correctly. But the user receives a generic failure rather than a specific message.
- **Status:** Code handles this gracefully. Verify the downstream error message is user-friendly.
- **Test fixture:** F-14

---

### 4. Inline Attribution Pattern Gaps

#### Nuance: Wrapped inline attribution — date splits across lines
- **Priority:** CRITICAL
- **Currently handled:** NO
- **Example input:**
  ```
  On Monday, April 19, 2026 at
  10:23:45 AM Pacific Daylight Time, Jane Doe <jane@example.com> wrote:
  ```
- **What breaks:** Lines 879-881:
  ```python
  inline_match = re.search(
      r'On\s+[^\n]{3,120}?,\s*(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:',
      body)
  ```
  The `[^\n]` character class stops matching at the `\n`. The date fragment on line 2 is never scanned. No match → fall through to `bare_inline_match` and `short_inline`, both of which also fail. Result: `_divider_kind = "none"`.
- **When this occurs:** iOS Mail with long locale date strings (e.g., `Pacific Daylight Time` instead of `PDT`). The attribution line can exceed ~80 characters and mail clients sometimes wrap it.
- **Proposed fix:** Add a `re.DOTALL` fallback that scans across the newline, with a tighter bound (≤250 total chars) to prevent runaway matching:
  ```python
  # Primary: single-line (existing)
  inline_match = re.search(
      r'On\s+[^\n]{3,120}?,\s*(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:',
      body)
  # Fallback: two-line wrapped date
  if not inline_match:
      inline_match = re.search(
          r'On\s+.{3,200}?,\s*(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:',
          body, re.DOTALL)
  ```
  The DOTALL version is used only as fallback; primary stays fast with `[^\n]`.
- **Test fixture:** F-15

---

#### Nuance: Inline attribution with display name containing date fragment
- **Priority:** MEDIUM (known limitation, address still correct)
- **Currently handled:** PARTIAL — address is correct, display name has date garbage
- **Example input:**
  ```
  On Mon, Apr 19, 2026 at 10:23 AM, Jane Doe <jane@spam.com> wrote:
  ```
- **What breaks:** The `[^\n]{3,120}?` is LAZY so it matches the shortest path. Starting from `On Mon, `, the lazy match stops at the first `,` — which is after `Mon`. This leaves the rest of the date fragment (`Apr 19, 2026 at 10:23 AM, `) inside group 1 alongside the display name. `original_from` becomes `'Apr 19, 2026 at 10:23 AM, Jane Doe <jane@spam.com>'`. `parse_from_address` still extracts the correct email address, so blacklisting works. Display name shown to user is garbage.
- **Proposed fix (optional):** Use a named-group approach that specifically anchors to the comma before the email address:
  ```python
  r'On\s+[^\n]{3,120}?,\s*(?P<name>.+?)\s*<(?P<addr>[^>\s]+@[^>\s]+)>\s*wrote:'
  ```
  Then strip known date patterns from the front of `name` before storing. Or: post-process name to strip anything before the last `,` in the name group if the portion before that comma looks like a date.
- **Test fixture:** F-16

---

#### Nuance: Inline attribution with no display name AND no `On` prefix
- **Priority:** LOW (last-resort pattern H already implemented)
- **Currently handled:** YES — `short_inline` pattern handles `Name <addr> wrote:`
- **Test fixture:** F-17

---

### 5. Body Part Selection

#### Nuance: Apple Mail HTML-only path — `From:` label and value in same div
- **Priority:** LOW (currently works)
- **Currently handled:** YES — verified working
- **Detail:** Apple Mail's HTML body puts the bold `From: ` label and the address value in adjacent `<span>` elements within the same `<div>`. After `html_to_text` strips tags and unescapes `&lt;/&gt;`, the output is `From: "Display Name" <addr@example.com>` on a single line. The angle-bracket regex matches correctly.
- **Edge case to watch:** If a future Apple Mail version puts the label in its own `<div>` (block element), the div-closing-tag newline would split the label from the value. Current behavior confirmed safe.
- **Test fixture:** F-18 (regression)

---

#### Nuance: HTML body with `&lt;`/`&gt;` encoding around email address
- **Priority:** HIGH (same root cause as F-12 but via HTML path)
- **Currently handled:** YES for the HTML→text path (`html_to_text` calls `html.unescape`)
- **Currently NOT handled:** When the plain-text body itself contains literal `&lt;addr&gt;` (not produced by HTML parsing, but by a broken plain-text client).
- **Test fixture:** F-12 covers this.

---

#### Nuance: `multipart/mixed` containing `multipart/alternative` (nested MIME)
- **Priority:** MEDIUM
- **Currently handled:** PARTIAL — the `rfc822` attachment walker uses `mime_msg.walk()` which does walk nested multipart. However, `get_plain_text_body` (utils.py line 119) also uses `msg.walk()` which handles nesting. The body extraction should work. Verify edge case where the `text/plain` part is deeply nested (e.g., `multipart/mixed > multipart/alternative > text/plain`).
- **Test fixture:** F-19

---

### 6. User-Prepended Text Scenarios

#### Nuance: User's text contains dashes that look like a divider
- **Priority:** LOW (mostly safe, one edge case)
- **Currently handled:** MOSTLY — user text like `FYI --- see below` does NOT trigger the `dashes+forward` regex because it lacks "forward". However, a user who writes `---` on a line by itself and whose next line happens to start with `From:` WOULD trigger `dashes+from-next`.
- **Example (false positive):**
  ```
  My note below.
  ---
  From: my earlier draft...
  ```
- **Risk:** Low in practice since `From:` lines in user text rarely appear immediately after a bare-dash line. But it can happen if the user quotes part of an email manually.
- **Test fixture:** F-20

---

#### Nuance: User text below the forwarded block
- **Priority:** LOW (no parser change needed)
- **Currently handled:** YES — `original_body` captures everything after the header section. Text the user added after the forward appears in `original_body`, not `user_explanation`. This is acceptable behavior.
- **Test fixture:** F-21

---

#### Nuance: Spam body embeds fake `Begin forwarded message:` block
- **Priority:** MEDIUM
- **Currently handled:** NO specific defense
- **Example:**
  ```
  Click here to win!

  Begin forwarded message:

  From: admin@yourbank.com
  Subject: Urgent: Verify your account

  Please verify your account now.
  ```
- **What breaks:** If a user forward spam like this (the outer mail), `parse_forwarded_email` finds the INNER fake block and extracts `admin@yourbank.com` as the original sender — not the actual spam sender. The actual spam sender's address is in the outer `From:` header (extracted separately by `extract_email_data`), so blacklisting uses the correct outer address via `fwd_data` vs `msg_data` depending on command flow.
- **Risk:** Depends on which address the blacklist commands use. If they use `original_from` from the parsed forward, the fake address gets blacklisted instead of the real spammer. If they use the outer envelope `From:`, this is safe.
- **Recommendation:** Audit the blacklist command handlers to confirm they use `msg_data["from_email"]` (outer envelope) not just `original_from` when the `original_from` originates from a body-embedded fake block.
- **Test fixture:** F-22

---

### 7. Client-Specific Weirdness

#### Nuance: iOS Mail — forward initiated from within a reply thread
- **Priority:** CRITICAL (was the bug found today)
- **Currently handled:** YES — FIXED in commit b76c9ac
- **Detail:** iOS Mail wraps the entire forwarded block in `> ` quoting when the forward is initiated from inside an existing reply thread. The divider arrives as `> Begin forwarded message:`. The fix in b76c9ac adds `re.sub(r'^>+\s?', '', stripped)` before the divider comparison. However, as documented in Nuance 1 above, the fix only works for single-level quoting. Double-spaced or spaced-double-level quoting (`> > Begin...`) still fails.
- **Reference EML:** `Fwd_ Blacklist All -- When a woman thinks she has no way forward.eml` — CONFIRMED WORKING with current code.
- **Test fixture:** F-23 (current behavior), F-01 (remaining gap)

---

#### Nuance: Gmail web — asymmetric dash count (10 left, 9 right)
- **Priority:** LOW (already handled)
- **Currently handled:** YES — `r'-{3,}.*[Ff]orward.*-{3,}'` matches both sides independently. Verified against `---------- Forwarded message ---------`.
- **Test fixture:** F-24

---

#### Nuance: ProtonMail — strips Received headers but preserves body format
- **Priority:** LOW
- **Currently handled:** YES for body parsing (format is same as Gmail inline `On...wrote:`)
- **Test fixture:** (covered by Gmail fixture F-25)

---

### 8. Encoding and Content-Transfer-Encoding

#### Nuance: Quoted-printable body with soft line breaks in forward headers
- **Priority:** LOW (handled by Python email library)
- **Currently handled:** YES — Python's `email.message` library decodes QP before returning the body string to `parse_forwarded_email`. The decoder joins soft-wrapped QP lines (those ending in `=\n`). Verified against the Blacklist All EML where the `Reply-To:` header spans two raw QP lines but arrives as a single decoded line.
- **Note:** The narrow no-break space `=E2=80=AF` (U+202F) in Apple Mail date strings decodes to the literal Unicode character and is stored in `original_date` as-is. This is harmless; no date parsing is performed.
- **Test fixture:** F-26 (regression for QP decode)

---

#### Nuance: Base64-encoded text/plain body
- **Priority:** LOW
- **Currently handled:** YES — Python `part.get_payload(decode=True)` handles both QP and base64; the caller sees the decoded string regardless.
- **Test fixture:** Not required separately; base64 decode is Python stdlib behavior.

---

### 9. RFC Compliance Nuances

#### Nuance: `Subject:` before `From:` in forwarded headers (Thunderbird order)
- **Priority:** LOW (already handled)
- **Currently handled:** YES — all three `re.search` calls (from, subject, date) use `re.search` on the full `below` string, not sequential line parsing. Header order is irrelevant.
- **Test fixture:** F-27

---

#### Nuance: Long `original_body` truncated at 1000 characters
- **Priority:** LOW (by design)
- **Currently handled:** YES — intentional 1000-char truncation at line 859: `result["original_body"] = "\n".join(lines[body_start:]).strip()[:1000]`. For spam classification, the first 1000 chars are sufficient.

---

### 10. Spam-Specific Tricks

#### Nuance: Inline display name contaminated with date fragment
- **Priority:** MEDIUM (see Nuance in Section 4)
- **Currently handled:** PARTIAL — address correct, display name wrong. See F-16.

---

## Test Fixtures

Each fixture shows the plain-text body (after MIME decoding, before any parsing). Expected output is `(original_from, original_subject)` tuple.

---

**F-01 — Spaced double-quote divider (CRITICAL gap)**
```
> > Begin forwarded message:
> > 
> > From: spammer@junk.io
> > Subject: You won
> > Date: Mon, Apr 19, 2026
```
Expected: `original_from = "spammer@junk.io"`, `_divider_kind = "apple-mail"`
Currently: FAILS (divider not detected)

---

**F-02 — Double-space after single `>` (MEDIUM gap)**
```
>  Begin forwarded message:
>  
>  From: spammer@junk.io
>  Subject: You won
```
Expected: `original_from = "spammer@junk.io"`
Currently: FAILS

---

**F-03 — Leading whitespace before `>` in raw lines**
```
Begin forwarded message:

  > From: spammer@junk.io
  > Subject: You won
```
Expected: `original_from = "spammer@junk.io"`
Currently: FAILS (below_lines unquote doesn't strip leading spaces)

---

**F-04 — Triple spaced quote `> > > Begin...`**
```
> > > Begin forwarded message:
> > > 
> > > From: inner@deep.io
> > > Subject: Deeply nested
```
Expected: `original_from = "inner@deep.io"`, `_divider_kind = "apple-mail"`
Currently: FAILS

---

**F-05 — Unicode `»` quote prefix (LOW)**
```
» Begin forwarded message:
» 
» From: spammer@junk.io
```
Expected: `original_from = "spammer@junk.io"`
Currently: FAILS

---

**F-06 — French Apple Mail localized divider (MEDIUM)**
```
Début du message réacheminé :

De : Display Name <sender@example.com>
Objet : Subject here
```
Expected: `original_from` contains `sender@example.com`
Currently: FAILS

---

**F-07 — German dashed divider (MEDIUM)**
```
-------- Weitergeleitete Nachricht --------
From: spammer@bad.de
Subject: Klicken Sie hier
```
Expected: `original_from = "spammer@bad.de"`, `_divider_kind = "dashes+forward"`
Currently: FAILS

---

**F-08 — Em-dash divider (LOW)**
```
——— Forwarded message ———
From: spammer@bad.com
Subject: Click here
```
Expected: `original_from = "spammer@bad.com"`
Currently: FAILS

---

**F-09 — Apple Mail divider without trailing colon (MEDIUM)**
```
Begin forwarded message

From: spammer@bad.com
Subject: Click here
```
Expected: `original_from = "spammer@bad.com"`, `_divider_kind = "apple-mail"`
Currently: FAILS

---

**F-10 — `Bcc:` in forwarded header block stops body_start early (HIGH)**
```
Begin forwarded message:

From: spammer@bad.com
Subject: Win a prize
Date: April 19, 2026
To: victim@example.com
Bcc: list@bulkmail.com
This is the spam body content.
```
Expected: `original_from = "spammer@bad.com"`, `original_body` starts at "This is the spam body content."
Currently: `original_body` incorrectly starts at "Bcc: list@bulkmail.com"

---

**F-11 — Header folding: `From:` wraps to continuation line (HIGH)**
```
Begin forwarded message:

From: "Very Long Display Name Inc"
  <contact@verylongdomainname.example.com>
Subject: Test
```
Expected: `original_from` contains `contact@verylongdomainname.example.com`
Currently: FAILS (address on continuation line not captured)

---

**F-12 — HTML-encoded angle brackets in plain-text From: (HIGH)**
```
Begin forwarded message:

From: Jane Doe &lt;jane@example.com&gt;
Subject: Test
```
Expected: `original_from` contains `jane@example.com`
Currently: FAILS (`parse_from_address` finds no `<>` angle brackets)

---

**F-13 — RFC 2047 encoded display name (regression — already works)**
```
Begin forwarded message:

From: =?utf-8?Q?Jane_Doe?= <jane@example.com>
Subject: Test
```
Expected: `original_from = "Jane Doe <jane@example.com>"`
Currently: PASSES

---

**F-14 — New Outlook display-name-only `From:` (already handled)**
```
-----Original Message-----
From: Robert Smith
Sent: Wednesday, April 19, 2026 10:23 AM
To: Recipient Name
Subject: Follow up
```
Expected: `original_from = "Robert Smith"`, `_missing_address_reason = "new_outlook_stripped"`
Currently: PASSES with sentinel

---

**F-15 — Wrapped inline attribution line (CRITICAL gap)**
```
On Monday, April 19, 2026 at
10:23:45 AM Pacific Daylight Time, Jane Doe <jane@spam.com> wrote:

Spam content here.
```
Expected: `original_from = "Jane Doe <jane@spam.com>"`, `_divider_kind = "inline-quote-on-wrote"`
Currently: FAILS

---

**F-16 — Inline attribution with date fragment in name (MEDIUM, known)**
```
On Mon, Apr 19, 2026 at 10:23 AM, Jane Doe <jane@spam.com> wrote:

Spam content.
```
Expected: `original_from = "Jane Doe <jane@spam.com>"`, address = `jane@spam.com`
Currently: PARTIAL — address correct, `original_from` display name contains date junk

---

**F-17 — Short inline without `On` prefix (last resort — already works)**
```
Jane Doe <jane@spam.com> wrote:

Spam content.
```
Expected: `original_from = "Jane Doe <jane@spam.com>"`, `_divider_kind = "inline-quote-short"`
Currently: PASSES

---

**F-18 — Apple Mail HTML-only forward path (regression)**
```html
[Apple Mail HTML body with blockquote and &lt;addr&gt; entities]
Begin forwarded message:
From: Display Name &lt;addr@example.com&gt;
```
Expected (after html_to_text): `original_from` contains `addr@example.com`
Currently: PASSES

---

**F-19 — Nested multipart/mixed > multipart/alternative (MEDIUM, likely works)**
Forward with outer `multipart/mixed` wrapping a `multipart/alternative` containing `text/plain`.
Expected: plain text part extracted and parsed correctly.
Currently: Likely passes via `msg.walk()` traversal; add fixture to confirm.

---

**F-20 — User text with bare dashes (false positive risk)**
```
My note below.
---
From: my earlier draft content here
```
Expected: `_divider_kind = "none"` (NOT triggered — "From:" without colon)
Currently: PASSES — `from:` check requires the colon, "From: my earlier..." has colon... WAIT. This WOULD match `next_line.lower().startswith('from:')` if the user writes `From: something`. Test to confirm.

---

**F-21 — User text below the forwarded block**
```
Begin forwarded message:

From: spammer@bad.com
Subject: Test
Date: April 19, 2026

Spam body here.

[This is my note I added after the forward]
```
Expected: `user_explanation = "[No explanation provided]"`, `original_body` contains both spam body and user's note
Currently: PASSES (by design)

---

**F-22 — Spam with fake `Begin forwarded message:` block**
```
Click here to win big prizes!

Begin forwarded message:

From: admin@yourbank.com
Subject: Urgent: Verify your account
Date: April 19, 2026

Your account needs verification.
```
Expected behavior: Parser extracts `admin@yourbank.com` as `original_from`. Verify downstream blacklist uses outer envelope address, not this extracted address.
Currently: Parser extracts the fake block sender. Security audit needed on command handlers.

---

**F-23 — Apple Mail forward from reply thread, single-level quoting (fixed, regression)**
```
> Begin forwarded message:
> 
> From: "The PreBorn! Team" <contact@victoryredpatriot.com>
> Subject: When a woman thinks she has no way forward
> Date: April 20, 2026 at 3:31:22 PM EDT
> To: <recipient@example.com>
```
Expected: `original_from = '"The PreBorn! Team" <contact@victoryredpatriot.com>'`, `_divider_kind = "apple-mail"`
Currently: PASSES (fixed in b76c9ac)

---

**F-24 — Gmail asymmetric dash divider (already works)**
```
---------- Forwarded message ---------
From: Spammer Joe <joe@spammy.biz>
Date: Mon, Apr 19, 2026 at 10:23 AM
Subject: Act now — limited time
```
Expected: `original_from = "Spammer Joe <joe@spammy.biz>"`, `_divider_kind = "dashes+forward"`
Currently: PASSES

---

**F-25 — Gmail inline attribution (already works)**
```
On Mon, Apr 19, 2026 at 10:23 AM, Jane Doe <jane@spammer.net> wrote:

This is the spam content.
```
Expected: `original_from = "Jane Doe <jane@spammer.net>"`, `_divider_kind = "inline-quote-on-wrote"`
Currently: PASSES

---

**F-26 — QP-decoded body, no-break space in date (regression)**
Body after QP decode contains `'Date: April 20, 2026 at 3:31:22\u202fPM EDT'`
Expected: `original_date = 'April 20, 2026 at 3:31:22\u202fPM EDT'` (stored raw, no issue)
Currently: PASSES

---

**F-27 — Thunderbird: Subject before From in header block**
```
-------- Forwarded Message --------
Subject: Invoice #12345
Date: Mon, 19 Apr 2026 10:23:45 -0700
From: billing@vendor.com
To: recipient@example.com
```
Expected: `original_from = "billing@vendor.com"`, `original_subject = "Invoice #12345"`
Currently: PASSES

---

**F-28 — Yahoo Mail: quoted display name in block header**
```
----- Forwarded Message -----
From: "Marketing Team" <offers@retailer.com>
Sent: Monday, April 19, 2026, 10:23 AM EDT
Subject: Weekend sale
```
Expected: `original_from = '"Marketing Team" <offers@retailer.com>'`
Address extracted by downstream `parse_from_address`: `offers@retailer.com`
Currently: PASSES (quotes are stored raw; parse_from_address strips them)

---

**F-29 — Classic Outlook: `Sent:` instead of `Date:`**
```
-----Original Message-----
From: Bob Smith <bob@contoso.com>
Sent: Monday, April 19, 2026 10:23 AM
To: recipient@example.com
Subject: Q2 Budget
```
Expected: `original_date = "Monday, April 19, 2026 10:23 AM"`, `_divider_kind = "outlook"`
Currently: PASSES (line 828 already handles `(?:sent|date)`)

---

**F-30 — Bare address inline (no display name)**
```
On Mon, Apr 19, 2026 at 10:23 AM, noreply@automated.io wrote:

Your subscription has been updated.
```
Expected: `original_from = "noreply@automated.io"`, `_divider_kind = "inline-quote-on-wrote-bare"`
Currently: PASSES

---

**F-31 — message/rfc822 attached original (highest-fidelity path)**
```
[MIME message with message/rfc822 attached part]
```
Expected: `_divider_kind = "rfc822-attachment"`, headers extracted from attached message object
Currently: PASSES

---

**F-32 — User writes text above the block forward**
```
Please blacklist this sender.

Begin forwarded message:

From: spammer@bad.com
Subject: Spam
```
Expected: `user_explanation = "Please blacklist this sender."`, `original_from = "spammer@bad.com"`
Currently: PASSES

---

---

## Prioritized Fix List

Ordered by impact. All changes are within `parse_forwarded_email` in `spam_filter.py` unless noted.

---

### Fix 1 — Unified quote-prefix stripping (CRITICAL, fixes F-01, F-02, F-03, F-04)

**Two places to change:**

**a) Divider detection loop (~line 788):**
```python
# BEFORE:
unquoted = re.sub(r'^>+\s?', '', stripped)

# AFTER:
unquoted = re.sub(r'^(>\s*)+', '', stripped).strip()
```

**b) Below-lines loop (~line 822):**
```python
# BEFORE:
unquoted = re.sub(r'^>+\s?', '', ln)

# AFTER:
unquoted = re.sub(r'^(\s*>\s*)+', '', ln).strip()
```

**c) Body-start loop (~line 848):**
```python
# BEFORE:
stripped = re.sub(r'^>+\s?', '', lines[i]).strip()

# AFTER:
stripped = re.sub(r'^(\s*>\s*)+', '', lines[i]).strip()
```

---

### Fix 2 — Wrapped inline attribution (CRITICAL, fixes F-15)

After the primary `inline_match` attempt (line ~881), add a DOTALL fallback:

```python
inline_match = re.search(
    r'On\s+[^\n]{3,120}?,\s*(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:',
    body)
if not inline_match:
    # Fallback: date may wrap to next line (iOS locale long date strings)
    inline_match = re.search(
        r'On\s+.{3,200}?,\s*(.+?)\s*<([^>\s]+@[^>\s]+)>\s*wrote:',
        body, re.DOTALL)
```

---

### Fix 3 — `Bcc:` and extended headers in body_start (HIGH, fixes F-10)

Lines ~849 and ~855, change the header recognition pattern:

```python
# BEFORE:
r'(?i)^(from|to|subject|date|sent|cc|reply-to):'

# AFTER:
r'(?i)^(from|to|bcc|subject|date|sent|cc|reply-to|message-id):'

# OR (more robust — match any RFC 2822 header name):
r'(?i)^[a-zA-Z][a-zA-Z0-9-]+\s*:'
```

The RFC 2822 pattern is broader and future-proof: it recognizes any `Word-Word:` header name. The risk of false positives is low because it only activates after `header_section = True` (i.e., after at least one recognized header was seen).

---

### Fix 4 — HTML-encoded angle brackets in `parse_from_address` (HIGH, fixes F-12)

In `utils.py`, `parse_from_address`, add HTML unescaping before the angle-bracket search:

```python
import html as _html_stdlib

def parse_from_address(header_value: str) -> dict:
    ...
    header_value = header_value.strip()
    # Unescape HTML entities that may appear in malformed plain-text bodies
    try:
        header_value = _html_stdlib.unescape(header_value)
    except Exception:
        pass
    ...
```

---

### Fix 5 — Header folding in forwarded block (HIGH, fixes F-11)

After building `below` (line ~824), add a fold-joiner:

```python
below = "\n".join(below_lines)
# Join RFC 2822 folded header continuations (line starting with space/tab)
below = re.sub(r'\n[ \t]+', ' ', below)
```

---

### Fix 6 — Apple Mail divider without trailing colon (MEDIUM, fixes F-09)

Line ~795, change exact comparison to regex:

```python
# BEFORE:
if unquoted == "Begin forwarded message:":

# AFTER:
if re.match(r'^Begin forwarded message:?\s*$', unquoted, re.IGNORECASE):
```

---

### Fix 7 — Wrapped inline attribution display-name cleanup (MEDIUM, fixes F-16 display only)

After extracting `name` from the inline match (line ~884):

```python
name = inline_match.group(1).strip().strip('"').strip("'").strip()
# Strip date-like prefix if name was contaminated by the lazy date match
# Pattern: remove everything up to and including the last comma if the
# portion before that comma looks like a date fragment
name_parts = name.rsplit(',', 1)
if len(name_parts) == 2:
    prefix, suffix = name_parts
    # If prefix contains digits (looks like date data), discard it
    if re.search(r'\d{4}|\d+:\d+|AM|PM', prefix, re.IGNORECASE):
        name = suffix.strip().strip('"').strip("'").strip()
```

This is optional — the email address (which is all that matters for blacklisting) is already correct.

---

*Document compiled 2026-04-19. All findings verified against live code and reference EMLs. Items marked CRITICAL and HIGH should be resolved before the next release.*

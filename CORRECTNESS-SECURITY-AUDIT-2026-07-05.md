# MailWarden Correctness & Security Audit — 2026-07-05

**Scope:** fresh-eyes read-only audit of branch `calibration-security-build1` @ `cba6865` (v1.6.0-beta.19), requested by Matt as part of a strategic fitness-for-purpose review. Focus areas: cross-feature interactions of the four newest features (F1 Dashboard Approve `77be272`, F2 Restore panel `7300cbc`, F3 enabled-default `cb12e48`, F4 Train-folder contradiction guard `9ff01c6`), the live fetch→classify→act corridor, false-positive error paths, and credential/security handling.

**Method:** static review by four parallel Opus investigations, every finding independently re-verified against cited code before inclusion. Prior audit documents (June 11 comprehensive audit; `INTEGRATION-AUDIT-2026-07-03.md`, all 20 findings landed) were read first; nothing here duplicates an already-fixed item. No code was executed against external APIs.

**Status: FINDINGS ONLY — no fixes applied in this session (per Matt's instruction: assessment, not code).**

---

## HIGH

### 1. A failed spam-move is still recorded as "processed" — the spam message is silently stranded in the inbox forever
- `payload/MailWarden/src/spam_filter.py:6087-6090` (`execute_spam_action`, default `"junk"` branch): `move_to_junk` failure returns the string `"[MOVE FAILED to {junk_folder}]"` — the function does not raise.
- `payload/MailWarden/src/spam_filter.py:8972-8981`: the caller checks `if "FAILED" in action` only to log an error and bump `total_errors`; it does not skip the record-as-processed step below.
- `payload/MailWarden/src/spam_filter.py:9015-9024`: `cache_this = (not dry_run) or (verdict != "spam")`. In a real (non-dry-run) run this is unconditionally `True`, so `_record_processed(processed, ...)` runs regardless of whether the move succeeded.
- **Failure scenario:** IMAP `COPY`/`STORE`/`EXPUNGE` fails mid-tick (dropped connection, permission error, provider quirk) for a message correctly classified SPAM. The UID is added to `processed_ids` in the same tick, so the message is never retried — it sits in the inbox unmoved while MailWarden's own logs and `decisions.log` say it was moved. State-corruption / silent-failure bug; defeats the app's core promise on the affected message.

### 2. IMAP and SMTP connections do not verify the server's TLS certificate or hostname — account passwords are exposed to an active man-in-the-middle
- `payload/MailWarden/src/spam_filter.py:5641` (`connect_imap`): `imaplib.IMAP4_SSL(account["imap_host"], account["imap_port"], timeout=15.0)` passes no `ssl_context`.
- `payload/MailWarden/src/utils.py:52` (`SMTP_SSL`, port-465 path) and `utils.py:63` (`server.starttls()`) — neither passes a `context`.
- Mechanism independently verified in this repo's Python: `imaplib.IMAP4_SSL.__init__` falls back to `ssl._create_stdlib_context()`, whose `check_hostname == False` and `verify_mode == CERT_NONE`. `smtplib` defaults the same way (PEP 476 deliberately excluded imaplib/smtplib/poplib/ftplib from verify-by-default).
- This contradicts the June audit's "TLS verification is solid" conclusion — that check only confirmed the absence of an explicit `ssl._create_unverified_context()` call and missed that the stdlib default for these modules is itself unverified.
- **Exposure scenario:** the filter re-authenticates every launchd wake (every 5–15 min). An attacker on the same network (rogue Wi-Fi AP, ARP/DNS spoofing, compromised router) presents any certificate — self-signed, expired, wrong domain — the handshake succeeds, and the IMAP/SMTP password is handed over. TLS as configured defeats only passive sniffing.
- **Fix shape (next build):** one line per socket — `ssl_context=ssl.create_default_context()` for IMAP4_SSL, `context=ssl.create_default_context()` for SMTP_SSL/starttls. The certifi CA-bundle wiring for `create_default_context()` already exists in `app/launcher.py:49-61`.
- Related positive: June finding C1 (command-email auth) is confirmed remediated — `_command_sender_is_owner` (`spam_filter.py:2826`) is AND-ed at every call site with `_command_auth_ok` (`:2853`), which performs SPF/DKIM/DMARC or authenticated-submission checks.

## MEDIUM

### 3. Dashboard Approve and email "YES" for the same false-positive proposal can create two duplicate active rules
- `app/mailwarden_app/config_io.py:840-916` (`apply_fp_narrowing_from_pending`) and the engine's parallel FP-apply arm at `payload/MailWarden/src/spam_filter.py:8237-8241` both mint a **fresh** refinement id at apply time via `_fp_narrowing_to_refinement`/`_mint_refinement_id` (`spam_filter.py:3339-3379`) — unlike the spam-example twin (`config_io.py:588`), which reuses the proposal's pre-minted fixed id and is therefore idempotent across the two channels.
- The engine's `_resolved_sfid_reply` check (`spam_filter.py:7910`) reads a pending-conversation snapshot loaded once per run, so it cannot see a Dashboard approval that lands mid-tick.
- **Failure scenario:** user clicks Approve in the Dashboard AND replies "YES" to the FP-analysis email before the next filter tick (either order). Result: two `verdict:"legitimate"` refinements with different `R-` ids for the same narrowing — duplicate cards in Signal History, split attribution weight, two `applied` log events. Not data-corrupting and removable via Delete, but a real, reachable divergence introduced by combining F1 with the pre-existing email path.

### 4. Deterministic prompt-injection/marker hard-junking can still move legitimate mail without any AI review (residual of June audit's C6)
- Still present in current `utils.py` marker-based detectors, consumed pre-classifier in `spam_filter.py`. Same class the June audit flagged (legit AI/marketing/quote-transcript email hard-junked deterministically). It was logged then as a `[MATT DECIDES]` product item and never assigned to a fix batch — not a regression, but still-open exposure that bears directly on the false-positive criterion.

### 5. Plaintext credential storage (account passwords, SMTP password, Anthropic API key) with no macOS Keychain use
- `app/mailwarden_app/config_io.py:63-77` (API key), `:136-146` (account `password`), `:158-165` (smtp `password`) — all written cleartext to `~/MailWarden/config/config.json`. No `keychain`/`keyring`/`SecItem` reference anywhere in `app/mailwarden_app` or `payload/MailWarden/src` (grep confirmed).
- Mitigation: every write path verified `0o600` (`save_config`, and `save_config_atomic`'s `mkstemp`+`os.replace` leaves no world/group-readable window). That stops other local users — not same-user processes or unencrypted backups (Time Machine, cloud-synced home folders). Likely an accepted tradeoff; flagged for an explicit decision.

## LOW

### 6. Dead "not a match" reply instruction in the Train-folder reinforcement FYI (F4)
- `payload/MailWarden/src/learn_signals.py:1384` tells the owner to reply "not a match," but the reply corridor only routes replies carrying an `[SFID-...]`/`[MWR-...]` subject token (`spam_filter.py:3515`), and this FYI email carries neither — the correction is unroutable. Low impact: `match_count`/evidence are never rendered into the classifier prompt, so a wrongly-reinforced rule can't itself cause a bad classification; broken UX promise, not a state or false-positive bug.

---

## Checked and confirmed sound (explicit clean results)

- **Cross-process file locking is real.** App (`app/mailwarden_app/paths.py:24`) and engine (`spam_filter.py:42`) resolve `signals.json` to the identical installed path; `file_lock.py` is byte-identical in both trees; sidecar `flock` genuinely serializes Dashboard Approve/Restore against the filter engine and detached learner.
- **F1/F2 twin logic (config_io.py mirroring spam_filter.py) is faithful** except for the id-minting asymmetry in finding 3. `restore_refinement` ↔ `unretire_ai_refinement`, the exact-`"retired"` predicate, and the FP markdown parsers all match their engine counterparts (and are pinned by drift-guard tests).
- **F4's contradiction guard is not inert:** `verdict:"legitimate"` is genuinely persisted on FP-taught refinements (`learn_signals.py:785`, `spam_filter.py:3366`), so `handle_duplicate`'s check at `learn_signals.py:1309` has real rules to match against.
- **F3 (enabled-default) has no first-run hazard:** engine action sites already defaulted `.get("enabled", True)` pre-F3; every GUI-created account writes `enabled` explicitly; `dry_run` defaults `True`.
- **June C4 (confidence-threshold key) and June C5 (DKIM domain harvesting) are both fixed** in current code — verified independently.
- **Classification error paths fail safe:** API/parse failure → `continue`, explicitly NOT added to `processed_ids`, retried next tick; decision defaults to NOT_SPAM absent an explicit SPAM verdict at/above threshold.
- **No credential leakage into logs or IPC:** no account or config dict is logged or printed anywhere found; `dashboard_ipc.py` binds loopback-only and carries no credential; the API-key parameter threaded into `daily_report.build_report_body` is unused dead code, not leaked into the report.

## Priority recommendation

Findings 1 and 2 (HIGH) should be fixed before the next installer build. Finding 2 is a one-line-per-socket change with CA wiring already present. Findings 3–5 need Matt's product decisions; finding 6 is a copy/routing fix that can ride along with any build.
